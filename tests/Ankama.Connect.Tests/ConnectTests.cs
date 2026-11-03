using System.Net;
using System.Text;
using System.Text.Json;
using Ankama.Connect;
using Xunit;

namespace Ankama.Connect.Tests;

public sealed class ConnectTests
{
    private const string ChallengeUrl = "https://3f38f7f4f368.edge.sdk.awswaf.com/3f38f7f4f368/e1fcfc58118e/challenge.js";

    [Fact]
    public void ParsesStandardAndHistoricalProxyFormats()
    {
        var standard = ConnectionInput.ParseProxy("socks5://user:password@127.0.0.1:1080");
        var historical = ConnectionInput.ParseProxy("socks5://127.0.0.1:1080@user:password");

        Assert.Equal(new Uri("socks5://127.0.0.1:1080"), standard.Address);
        Assert.Equal(new Uri("socks5://127.0.0.1:1080"), historical.Address);
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
                return Script("// challenge");
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
           "'; middle parseInt('" + difficulty +
           "'); final parseInt('" + memory + "')";

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
