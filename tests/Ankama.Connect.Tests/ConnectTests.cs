using System.Net;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Ankama.Connect;
using Xunit;

namespace Ankama.Connect.Tests;

public sealed class ConnectTests
{
    private const string ChallengeUrl = "https://3f38f7f4f368.edge.sdk.awswaf.com/3f38f7f4f368/e1fcfc58118e/challenge.js";
    private const string ObfuscatedKey = "nMy3mwe1mtjImwuWmZvLywfIntnKogjLnZmXmJbKm2zInJHHmgnHmZq2yJK1nJbHywiZztvJzgy3ntnKnwu5oa";
    private static readonly string MathConstant = "0x" + new string('f', 220);

    [Fact]
    public void ParsesStandardAndHistoricalProxyFormats()
    {
        var standard = ConnectionInput.ParseProxy("socks5://user:password@127.0.0.1:1080");
        var historical = ConnectionInput.ParseProxy("socks5://127.0.0.1:1080@user:password");

        Assert.Equal(new Uri("socks5://127.0.0.1:1080"), standard.Address);
        Assert.Equal(new Uri("socks5://127.0.0.1:1080"), historical.Address);
    }

    [Fact]
    public void ExtractsTheBrowserSignalKeyFromTheChallengeScript()
    {
        var key = AwsBrowserSignal.ExtractKey("prefix '" + ObfuscatedKey + "' suffix");

        Assert.Equal(
            Convert.FromHexString("6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98"),
            key);
    }

    [Fact]
    public void GeneratesFingerprintAndTelemetryWithoutCapturedTemplates()
    {
        AwsBrowserSignal.UseChallengeScript(ObfuscatedKey + " 2.4.0 " + MathConstant);

        var fingerprint = JsonDocument.Parse(AwsBrowserSignal.CreateFingerprint(new Random(42)).Json);
        var telemetry = JsonDocument.Parse(AwsBrowserSignal.CreateTelemetry(new Random(43)).Json);
        var repeatedFingerprint = JsonDocument.Parse(AwsBrowserSignal.CreateFingerprint(new Random(44)).Json);
        var fingerprintRoot = fingerprint.RootElement;
        var telemetryRoot = telemetry.RootElement;
        var repeatedRoot = repeatedFingerprint.RootElement;

        var histogram = fingerprintRoot.GetProperty("canvas").GetProperty("histogramBins");
        Assert.Equal(256, histogram.GetArrayLength());
        Assert.Equal(36_000, histogram.EnumerateArray().Sum(value => value.GetInt32()));
        Assert.True(histogram.EnumerateArray().All(value => value.GetInt32() >= 0));
        Assert.NotEqual(-1844565796, fingerprintRoot.GetProperty("canvas").GetProperty("hash").GetInt32());
        Assert.Equal(
            repeatedRoot.GetProperty("canvas").GetProperty("hash").GetInt32(),
            fingerprintRoot.GetProperty("canvas").GetProperty("hash").GetInt32());
        Assert.Equal(
            repeatedRoot.GetProperty("canvas").GetProperty("histogramBins").EnumerateArray().Select(value => value.GetInt32()),
            histogram.EnumerateArray().Select(value => value.GetInt32()));
        Assert.Equal("2.4.0", fingerprintRoot.GetProperty("version").GetString());
        Assert.Equal("2.4.0", telemetryRoot.GetProperty("tVersion").GetString());
        Assert.True(fingerprintRoot.GetProperty("end").GetInt64() >= fingerprintRoot.GetProperty("start").GetInt64() + 130);
        Assert.True(telemetryRoot.GetProperty("end").GetInt64() >= telemetryRoot.GetProperty("start").GetInt64() + 1);
        Assert.True(telemetryRoot.GetProperty("ciba").GetProperty("start").GetInt64() <= telemetryRoot.GetProperty("start").GetInt64());
    }

    [Fact]
    public void ComputesTheAwsCanvasCrc32()
    {
        Assert.Equal<uint>(0xCbf43926, AwsCrc32.ComputeUInt32("123456789"));
        Assert.Equal("2639F4CB", AwsCrc32.ComputeChecksum("123456789"));
    }

    [Fact]
    public void GeneratesCoherentMathAndBrowserMetrics()
    {
        AwsBrowserSignal.UseChallengeScript(ObfuscatedKey + " 2.4.0 " + MathConstant);

        var fingerprint = JsonDocument.Parse(AwsBrowserSignal.CreateFingerprint(new Random(42)).Json).RootElement;
        var math = fingerprint.GetProperty("math");
        var tangent = double.Parse(math.GetProperty("tan").GetString()!, CultureInfo.InvariantCulture);
        var sine = double.Parse(math.GetProperty("sin").GetString()!, CultureInfo.InvariantCulture);
        var cosine = double.Parse(math.GetProperty("cos").GetString()!, CultureInfo.InvariantCulture);
        var metrics = fingerprint.GetProperty("metrics");

        Assert.Equal(tangent, sine / cosine, 12);
        Assert.InRange(metrics.GetProperty("canvas").GetInt32(), 110, 170);
        Assert.InRange(metrics.GetProperty("gpu").GetInt32(), 4, 10);
        Assert.InRange(metrics.GetProperty("cdp").GetInt32(), 9, 18);
    }

    [Fact]
    public void SerializesBrowserMetricsWithAwsFieldNames()
    {
        AwsBrowserSignal.UseChallengeScript(ObfuscatedKey + " 2.4.0 " + MathConstant);

        var metrics = AwsBrowserSignal.CreateFingerprint(new Random(42)).Metrics;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(metrics));
        var metric = document.RootElement[0];

        Assert.Equal("2", metric.GetProperty("name").GetString());
        Assert.Equal(1, metric.GetProperty("value").GetInt32());
        Assert.Equal("2", metric.GetProperty("unit").GetString());
    }

    [Fact]
    public async Task AwsClientCompletesTheFullChallengeSequence()
    {
        var telemetryCount = 0;
        using var handler = new RecordingHandler(async request =>
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync();
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri.StartsWith("https://auth.ankama.com/login/ankama", StringComparison.Ordinal))
                return Html($"<script src=\"{ChallengeUrl}\"></script><script>window.gokuProps = {{\"a\":\"b\"}};</script>");
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri == ChallengeUrl)
                return Script(ChallengeScript("input", "hmac", "eu-south-2", 3, 128));
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri.EndsWith("/inputs?client=browser", StringComparison.Ordinal))
                return Json("{\"challenge\":{\"input\":\"live-input\",\"region\":\"eu-west-1\"},\"difficulty\":4,\"memory\":256}");
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/mp_verify", StringComparison.Ordinal))
            {
                Assert.Contains("\"input\":\"live-input\"", body);
                Assert.Contains("\"region\":\"eu-west-1\"", body);
                Assert.Contains("\"goku_props\":{\"a\":\"b\"}", body);
                Assert.DoesNotContain("\"hmac\"", body);
                var metadata = JsonDocument.Parse(GetFormField(body, "solution_metadata")).RootElement;
                var solutionData = Convert.FromBase64String(GetFormField(body, "solution_data"));
                Assert.Equal(JsonValueKind.Null, metadata.GetProperty("solution").ValueKind);
                Assert.Equal(1024, solutionData.Length);
                Assert.All(solutionData, value => Assert.Equal(0, value));
                return Json("{\"token\":\"verify-token\"}");
            }
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/telemetry", StringComparison.Ordinal))
            {
                telemetryCount++;
                var existingToken = telemetryCount == 1 ? "verify-token" : "telemetry-token";
                Assert.Equal(existingToken, JsonDocument.Parse(body).RootElement.GetProperty("existing_token").GetString());
                return Json(telemetryCount == 1
                    ? "{\"token\":\"telemetry-token\",\"next_interval\":0}"
                    : "{\"token\":\"final-token\",\"next_interval\":0}");
            }

            throw new InvalidOperationException("Unexpected request: " + request.RequestUri);
        });

        using var client = new AwsWafTokenClient(handler);
        var pair = await client.GetTokenPairAsync();

        Assert.Equal("final-token", pair.NavigationToken);
        Assert.Equal("final-token", pair.Token);
        Assert.Equal(6, handler.Requests.Count);
        Assert.Equal(2, telemetryCount);
    }

    [Fact]
    public async Task AwsRefreshUsesOneTelemetryAndDoesNotRepeatVerification()
    {
        using var handler = new RecordingHandler(async request =>
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync();
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri == ChallengeUrl)
            {
                Assert.Equal("script", request.Headers.GetValues("sec-fetch-dest").Single());
                Assert.Equal("no-cors", request.Headers.GetValues("sec-fetch-mode").Single());
                return Script("// challenge " + ObfuscatedKey + " 2.4.0 " + MathConstant);
            }
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/telemetry", StringComparison.Ordinal))
            {
                Assert.Equal("text/plain", request.Content!.Headers.ContentType!.MediaType);
                Assert.Equal("initial-token", JsonDocument.Parse(body).RootElement.GetProperty("existing_token").GetString());
                return Json("{\"token\":\"refreshed-token\"}");
            }

            throw new InvalidOperationException("Unexpected refresh request: " + request.RequestUri);
        });

        using var client = new AwsWafTokenClient(handler);
        var pair = await client.RefreshTokenPairAsync(
            "initial-token",
            $"<script src=\"{ChallengeUrl}\"></script>");

        Assert.Equal("refreshed-token", pair.NavigationToken);
        Assert.Equal("refreshed-token", pair.Token);
        Assert.Equal(2, handler.Requests.Count);
        Assert.DoesNotContain(handler.Requests, request => request.Url.AbsolutePath.EndsWith("/inputs", StringComparison.Ordinal));
        Assert.DoesNotContain(handler.Requests, request => request.Url.AbsolutePath.EndsWith("/mp_verify", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LoginRefreshesTheEmbeddedSdkBeforeSendingCredentials()
    {
        var refreshes = 0;
        using var handler = new RecordingHandler(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/login/ankama")
                return Task.FromResult(LoginForm());
            if (path == "/login/ankama/form")
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found)
                {
                    Headers = { Location = new Uri("zaap://login?code=fixture-code") }
                });
            }
            if (path == "/token")
                return Task.FromResult(Json("{\"access_token\":\"access\",\"refresh_token\":\"refresh\"}"));
            if (path.EndsWith("/Account", StringComparison.Ordinal))
                return Task.FromResult(Json("{\"id\":42,\"uuid\":\"uuid\",\"type\":\"ankama\",\"login\":\"login\"}"));
            throw new InvalidOperationException("Unexpected request: " + request.RequestUri);
        });
        using var service = new AnkamaService(handler);

        var result = await service.LoginHttp(
            "login",
            "password",
            _ => Task.FromResult(new AwsWafTokenPair("initial-token", "initial-token")),
            (existingToken, pageHtml, _) =>
            {
                refreshes++;
                Assert.Equal("initial-token", existingToken);
                Assert.Contains("challenge.js", pageHtml);
                return Task.FromResult(new AwsWafTokenPair("refreshed-token", "refreshed-token"));
            });

        Assert.Equal("access", result.accessToken);
        Assert.Equal("refresh", result.refreshToken);
        Assert.Equal(42, result.info.Id);
        Assert.Equal(1, refreshes);
        Assert.Equal(4, handler.Requests.Count);
    }

    [Fact]
    public async Task LoginRecognizesTheRealBannedAccountMessage()
    {
        using var handler = new RecordingHandler(request => Task.FromResult(request.Method == HttpMethod.Get
            ? LoginForm()
            : Html("<p>Votre compte est banni définitivement.</p>")));
        using var service = new AnkamaService(handler);

        await Assert.ThrowsAsync<AnkamaBannedException>(() => service.LoginHttp("login", "password"));
        Assert.Equal(2, handler.Requests.Count);
    }

    private static HttpResponseMessage LoginForm() => Html(
        "<script src=\"https://edge.sdk.awswaf.com/challenge.js\"></script>" +
        "<form><input name='state' value='state'></form>");

    private static HttpResponseMessage Html(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "text/html")
    };

    private static HttpResponseMessage Script(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/javascript")
    };

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private static string ChallengeScript(
        string input,
        string hmac,
        string region,
        int difficulty,
        int memory)
        => "var _0x1234={}; ignored _0x1234[_0x5678(0x9abc)]='" + input +
           "',_0x1234[_0x5678(0xdef0)]='" + hmac +
           "',_0x1234[_0x5678(0x1234)]='" + region +
           "'; middle " + ObfuscatedKey + " 2.4.0 " + MathConstant + " parseInt('" + difficulty +
           "'); final parseInt('" + memory + "')";

    private static string GetFormField(string body, string name)
    {
        var marker = "name=" + name + "\r\n\r\n";
        var start = body.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "Champ multipart introuvable : " + name);
        start += marker.Length;
        var end = body.IndexOf("\r\n--", start, StringComparison.Ordinal);
        Assert.True(end > start, "Fin du champ multipart introuvable : " + name);
        return body[start..end];
    }

    private sealed record CapturedRequest(HttpMethod Method, Uri Url);

    private sealed class RecordingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handle) : HttpMessageHandler
    {
        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(new CapturedRequest(request.Method, request.RequestUri!));
            return await handle(request);
        }
    }
}
