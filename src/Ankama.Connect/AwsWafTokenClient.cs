using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ankama.Connect;

public sealed class AwsWafTokenClient : IDisposable
{
    private const string LoginUrl = "https://auth.ankama.com/login/ankama?code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&redirect_uri=zaap%3A%2F%2Flogin&client_id=102&direct=true&origin_tracker=https%3A%2F%2Fwww.ankama-launcher.com%2Flauncher";
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";

    private static readonly Regex ChallengeUrlPattern = new(
        "<script[^>]+src=[\"'](?<url>https?://[^\"']+challenge\\.js[^\"']*)[\"']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex GokuPropsPattern = new(
        @"window\.gokuProps\s*=\s*(?<props>\{.*?\})\s*;",
        RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(5));

    private readonly HttpClient _client;

    public AwsWafTokenClient(WebProxy? proxy = null)
        : this(CreateHandler(proxy))
    {
    }

    internal AwsWafTokenClient(HttpMessageHandler handler)
    {
        _client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        ConfigureDefaultHeaders();
    }

    public async Task<AwsWafTokenPair> GetTokenPairAsync(CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var ct = deadline.Token;

        var interstitial = await GetInterstitialAsync(ct);
        var challengeScript = await GetChallengeScriptAsync(interstitial.ChallengeUrl, ct);
        var embeddedChallenge = AwsWafChallenge.Parse(challengeScript);
        var challenge = await GetChallengeInputsAsync(interstitial.ChallengeUrl, embeddedChallenge, ct);
        var verifyToken = await VerifyChallengeAsync(
            interstitial.ChallengeUrl,
            challenge,
            interstitial.GokuProps,
            ct);
        var firstTelemetry = await SendTelemetryAsync(
            GetTelemetryUrl(interstitial.ChallengeUrl), verifyToken, CreateFirstTelemetryMetrics(), ct);
        await DelayAsync(firstTelemetry.NextInterval, ct);
        var finalTelemetry = await SendTelemetryAsync(
            GetTelemetryUrl(interstitial.ChallengeUrl), firstTelemetry.Token, CreateSecondTelemetryMetrics(), ct);

        return new AwsWafTokenPair(finalTelemetry.Token, finalTelemetry.Token);
    }

    public async Task<AwsWafTokenPair> RefreshTokenPairAsync(
        string existingToken,
        string pageHtml,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(existingToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(pageHtml);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var ct = deadline.Token;

        var challengeUrl = GetChallengeUrl(pageHtml);
        await GetChallengeScriptAsync(challengeUrl, ct);
        var refreshed = await SendTelemetryAsync(
            GetTelemetryUrl(challengeUrl),
            existingToken,
            CreateSecondTelemetryMetrics(),
            ct);
        return new AwsWafTokenPair(refreshed.Token, refreshed.Token);
    }

    public void Dispose() => _client.Dispose();

    private static HttpMessageHandler CreateHandler(WebProxy? proxy) => new HttpClientHandler
    {
        Proxy = proxy,
        UseProxy = proxy != null,
        AutomaticDecompression = DecompressionMethods.All
    };

    private void ConfigureDefaultHeaders()
    {
        _client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        _client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
        _client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("fr-FR");
        _client.DefaultRequestHeaders.Add("sec-ch-ua", "\"Chromium\";v=\"153\", \"Not_A Brand\";v=\"8\"");
        _client.DefaultRequestHeaders.Add("sec-ch-ua-mobile", "?0");
        _client.DefaultRequestHeaders.Add("sec-ch-ua-platform", "\"Windows\"");
    }

    private async Task<Interstitial> GetInterstitialAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, LoginUrl);
        AddNavigationHeaders(request);
        using var response = await _client.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AWS WAF : page de connexion HTTP {(int)response.StatusCode}.");

        var html = await response.Content.ReadAsStringAsync(cancellationToken);
        return ParseInterstitial(html);
    }

    private static string GetChallengeUrl(string html)
    {
        var match = ChallengeUrlPattern.Match(html);
        if (!match.Success)
            throw new InvalidOperationException("AWS WAF : SDK Edge introuvable dans la page de connexion.");

        return match.Groups["url"].Value;
    }

    private static Interstitial ParseInterstitial(string html)
    {
        var challengeUrl = GetChallengeUrl(html);
        JsonNode? gokuProps = null;
        var propsMatch = GokuPropsPattern.Match(html);
        if (propsMatch.Success)
        {
            gokuProps = JsonNode.Parse(propsMatch.Groups["props"].Value);
            if (gokuProps is not JsonObject)
                throw new InvalidOperationException("AWS WAF : propriétés du challenge invalides.");
        }

        return new Interstitial(challengeUrl, gokuProps);
    }

    private async Task<string> GetChallengeScriptAsync(string challengeUrl, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, challengeUrl);
        request.Headers.Referrer = new Uri("https://auth.ankama.com/");
        AddScriptHeaders(request);
        using var response = await _client.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AWS WAF : challenge HTTP {(int)response.StatusCode}.");

        return await response.Content.ReadAsStringAsync(cancellationToken);
    }

    private async Task<AwsWafChallenge> GetChallengeInputsAsync(
        string challengeUrl,
        AwsWafChallenge embeddedChallenge,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, GetBaseUrl(challengeUrl) + "/inputs?client=browser");
        AddCorsHeaders(request);
        using var response = await _client.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AWS WAF : entrées HTTP {(int)response.StatusCode}.");

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (JsonNode.Parse(json) is not JsonObject root ||
            root["challenge"] is not JsonObject challenge ||
            challenge["input"]?.GetValue<string>() is not { } input ||
            challenge["region"]?.GetValue<string>() is not { } region)
        {
            throw new InvalidOperationException("AWS WAF : entrées invalides.");
        }

        return new AwsWafChallenge(
            input,
            null,
            region,
            GetOptionalInt(root, "difficulty") ?? embeddedChallenge.Difficulty,
            GetOptionalInt(root, "memory") ?? embeddedChallenge.Memory);
    }

    private async Task<string> VerifyChallengeAsync(
        string challengeUrl,
        AwsWafChallenge challenge,
        JsonNode? gokuProps,
        CancellationToken cancellationToken)
    {
        var signal = AwsBrowserSignal.CreateFingerprint();
        var challengeNode = new JsonObject
        {
            ["input"] = challenge.Input,
            ["region"] = challenge.Region
        };
        if (challenge.Hmac is not null)
            challengeNode["hmac"] = challenge.Hmac;

        var solutionMetadata = new JsonObject
        {
            ["challenge"] = challengeNode,
            ["signals"] = new JsonArray(new JsonObject
            {
                ["name"] = "Zoey",
                ["value"] = new JsonObject { ["Present"] = signal.Encrypted }
            }),
            ["checksum"] = signal.Checksum,
            ["existing_token"] = null,
            ["client"] = "Browser",
            ["domain"] = "auth.ankama.com",
            ["metrics"] = JsonSerializer.SerializeToNode(CreateFingerprintMetrics()),
            ["goku_props"] = gokuProps,
            ["solution"] = null
        };
        var metadataJson = solutionMetadata.ToJsonString();
        var solutionData = Convert.ToBase64String(new byte[1024]);

        using var content = new MultipartFormDataContent(CreateWebKitBoundary());
        AddFormField(content, "solution_metadata", metadataJson);
        AddFormField(content, "solution_data", solutionData);

        var url = GetBaseUrl(challengeUrl) + "/mp_verify?region=" + Uri.EscapeDataString(challenge.Region);
        using var response = await PostAsync(url, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AWS WAF : vérification HTTP {(int)response.StatusCode}.");

        var result = await ReadTokenResponseAsync(response, cancellationToken);
        return result.Token;
    }

    private async Task<AwsTokenResponse> SendTelemetryAsync(
        string telemetryUrl,
        string existingToken,
        IReadOnlyList<object> metrics,
        CancellationToken cancellationToken)
    {
        var signal = AwsBrowserSignal.CreateTelemetry();
        var payload = new
        {
            existing_token = existingToken,
            awswaf_session_storage = "null",
            client = "Browser",
            signals = new[]
            {
                new
                {
                    name = "Zoey",
                    value = new { Present = signal.Encrypted }
                }
            },
            checksum = signal.Checksum,
            metrics
        };

        using var content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8);
        content.Headers.TryAddWithoutValidation("Content-Type", "text/plain;charset=UTF-8");
        using var response = await PostAsync(telemetryUrl, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AWS WAF : télémétrie HTTP {(int)response.StatusCode}.");

        return await ReadTokenResponseAsync(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> PostAsync(
        string url,
        HttpContent content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        request.Headers.Add("Origin", "https://auth.ankama.com");
        request.Headers.Referrer = new Uri("https://auth.ankama.com/");
        AddCorsHeaders(request);
        return await _client.SendAsync(request, cancellationToken);
    }

    private static void AddNavigationHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("sec-fetch-dest", "document");
        request.Headers.TryAddWithoutValidation("sec-fetch-mode", "navigate");
        request.Headers.TryAddWithoutValidation("sec-fetch-site", "none");
        request.Headers.TryAddWithoutValidation("sec-fetch-user", "?1");
        request.Headers.TryAddWithoutValidation("upgrade-insecure-requests", "1");
        request.Headers.TryAddWithoutValidation("priority", "u=0, i");
    }

    private static void AddScriptHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("sec-fetch-dest", "script");
        request.Headers.TryAddWithoutValidation("sec-fetch-mode", "no-cors");
        request.Headers.TryAddWithoutValidation("sec-fetch-site", "cross-site");
        request.Headers.TryAddWithoutValidation("sec-fetch-storage-access", "active");
        request.Headers.TryAddWithoutValidation("priority", "u=1");
    }

    private static void AddCorsHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("sec-fetch-dest", "empty");
        request.Headers.TryAddWithoutValidation("sec-fetch-mode", "cors");
        request.Headers.TryAddWithoutValidation("sec-fetch-site", "cross-site");
        request.Headers.TryAddWithoutValidation("priority", "u=1, i");
    }

    private static void AddFormField(MultipartFormDataContent content, string name, string value)
    {
        var field = new StringContent(value, Encoding.UTF8);
        field.Headers.ContentType = null;
        content.Add(field, name);
    }

    private static async Task<AwsTokenResponse> ReadTokenResponseAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("token", out var token) ||
            token.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(token.GetString()))
        {
            throw new InvalidOperationException("AWS WAF : réponse sans jeton valide.");
        }

        var nextInterval = root.TryGetProperty("next_interval", out var interval) && interval.ValueKind == JsonValueKind.Number
            ? interval.GetInt32()
            : 0;
        return new AwsTokenResponse(token.GetString()!, nextInterval);
    }

    private static async Task DelayAsync(int milliseconds, CancellationToken cancellationToken)
    {
        if (milliseconds > 0)
            await Task.Delay(Math.Min(milliseconds, 1000), cancellationToken);
    }

    private static string GetBaseUrl(string challengeUrl)
        => challengeUrl[..challengeUrl.LastIndexOf("/challenge.js", StringComparison.Ordinal)];

    private static string GetTelemetryUrl(string challengeUrl)
        => GetBaseUrl(challengeUrl) + "/telemetry";

    private static int? GetOptionalInt(JsonObject root, string name)
    {
        if (root.TryGetPropertyValue(name, out var value) && value is JsonValue number && number.TryGetValue<int>(out var result))
            return result;
        return null;
    }

    private sealed record AwsTokenResponse(string Token, int NextInterval);
    private sealed record Interstitial(string ChallengeUrl, JsonNode? GokuProps);

    private static string CreateWebKitBoundary()
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var boundary = new StringBuilder("----WebKitFormBoundary");
        for (var index = 0; index < 16; index++)
            boundary.Append(alphabet[Random.Shared.Next(alphabet.Length)]);
        return boundary.ToString();
    }

    private static object[] CreateFingerprintMetrics()
        => CreateMetrics(
            ("2", 1, "2"), ("100", 0, "2"), ("102", 1, "2"), ("111", 138, "2"),
            ("103", 6, "2"), ("104", 0, "2"), ("105", 0, "2"), ("106", 0, "2"), ("107", 0, "2"),
            ("110", 0, "2"), ("108", 1, "2"), ("101", 0, "2"), ("115", 1, "2"), ("114", 13, "2"),
            ("112", 0, "2"), ("3", 3.4, "2"), ("7", 0, "4"), ("1", 169.5, "2"),
            ("4", 3, "2"), ("5", 0.5, "2"), ("6", 173, "2"), ("0", 282.9, "2"), ("8", 1, "4"));

    private static object[] CreateFirstTelemetryMetrics()
        => CreateMetrics(
            ("12", 0.10059999999998581, "2"), ("200", 0, "2"), ("201", 0, "2"),
            ("13", 0.8656999999998334, "2"), ("10", 0, "4"), ("9", 0, "4"), ("11", 3.197900000000118, "2"));

    private static object[] CreateSecondTelemetryMetrics()
        => CreateMetrics(
            ("12", 0.053699999999935244, "2"), ("200", 0, "2"), ("201", 0, "2"),
            ("13", 0.5283999999999196, "2"), ("10", 0, "4"), ("9", 0, "4"), ("11", 0.893100000000004, "2"));

    private static object[] CreateMetrics(params (string Name, double Value, string Unit)[] values)
        => values.Select(value => new
        {
            name = value.Name,
            @value = Noisy(value.Value),
            unit = value.Unit
        }).ToArray();

    private static double Noisy(double value)
    {
        if (value <= 1) return value;
        var spread = Math.Max(0.05, Math.Abs(value) * 0.08);
        return Math.Round((value + (Random.Shared.NextDouble() * 2 - 1) * spread) * 1000d, MidpointRounding.AwayFromZero) / 1000d;
    }
}
