using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Ankama.Connect;

public sealed class AnkamaService : IDisposable
{
    private const string ChromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";

    public WebProxy? Proxy { get; set; }
    private HttpClient _client;
    private CookieContainer _cookies = new();
    private Dictionary<string, string> _formFields = new(StringComparer.Ordinal);
    private Uri _formUri = new("https://auth.ankama.com/login/ankama/form");
    private string? _lastLoginHtml;

    public AnkamaService(HttpMessageHandler? handler = null)
    {
        _client = CreateClient(handler ?? CreateHandler());
    }

    private HttpClientHandler CreateHandler() => new()
    {
        Proxy = Proxy,
        UseProxy = Proxy != null,
        CookieContainer = _cookies,
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
    };

    private static HttpClient CreateClient(HttpMessageHandler handler)
    {
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(ChromeUserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("fr-FR");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua", "\"Chromium\";v=\"153\", \"Not_A Brand\";v=\"8\"");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua-mobile", "?0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua-platform", "\"Windows\"");
        return client;
    }

    public void Initialize()
    {
        _client.Dispose();
        _client = CreateClient(CreateHandler());
    }

    public void Dispose() => _client.Dispose();

    public void SetAwsToken(string awsToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(awsToken);
        _cookies.Add(new Cookie("aws-waf-token", awsToken, "/", "auth.ankama.com") { Secure = true });
    }

    public async Task<(string accessToken, string refreshToken, AnkamaAccountInfo info)> LoginHttp(
        string login,
        string password,
        Func<CancellationToken, Task<AwsWafTokenPair>>? acquireAwsToken = null,
        Func<string, string, CancellationToken, Task<AwsWafTokenPair>>? refreshAwsToken = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(login);
        ArgumentException.ThrowIfNullOrEmpty(password);
        AwsWafTokenPair? awsTokens = null;
        if (acquireAwsToken != null)
        {
            awsTokens = await acquireAwsToken(ct);
            SetAwsToken(awsTokens.NavigationToken);
        }
        var (verifier, challenge, state) = await LoginStep1(ct);
        if (awsTokens != null && refreshAwsToken != null && _lastLoginHtml?.Contains("challenge.js") == true)
        {
            awsTokens = await refreshAwsToken(awsTokens.Token, _lastLoginHtml, ct);
            SetAwsToken(awsTokens.NavigationToken);
        }
        var existingToken = _cookies.GetCookies(new Uri("https://auth.ankama.com/"))["aws-waf-token"]?.Value;
        var result = await LoginStep2(login, password, verifier, challenge, state, awsTokens?.Token ?? existingToken, ct);
        if (result.retry)
            throw new InvalidDataException("Ankama : connexion HTTP refusée par CloudFront. Aucun renvoi automatique des identifiants.");
        var info = await GetAccountInfo(result.accessToken, ct);
        return (result.accessToken, result.refreshToken, info);
    }

    public async Task<(string codeVerifier, string codeChallenge, string state)> LoginStep1(CancellationToken ct = default)
    {
        var verifier = GenerateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var url = BuildLoginUrl(challenge);
        _formFields = new Dictionary<string, string>(StringComparer.Ordinal);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddNavigationHeaders(request, "none");
        using var response = await SendFollowingRedirects(request, ct);
        EnsureNoProtection(response, "l'ouverture du formulaire");
        response.EnsureSuccessStatusCode();
        _formUri = response.RequestMessage?.RequestUri ?? new Uri("https://auth.ankama.com/login/ankama/form");
        var html = await response.Content.ReadAsStringAsync(ct);
        _lastLoginHtml = html;
        string? state = null;
        foreach (Match input in Regex.Matches(html, @"<input\b[^>]*>", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
        {
            var attributes = Regex.Matches(input.Value,
                @"(?<name>[\w-]+)\s*=\s*(?:""(?<value>[^""]*)""|'(?<value>[^']*)'|(?<value>[^\s>]+))",
                RegexOptions.None, TimeSpan.FromSeconds(1));
            string? name = null, value = null, type = null;
            foreach (Match attribute in attributes)
            {
                if (attribute.Groups["name"].Value.Equals("name", StringComparison.OrdinalIgnoreCase))
                    name = WebUtility.HtmlDecode(attribute.Groups["value"].Value);
                if (attribute.Groups["name"].Value.Equals("value", StringComparison.OrdinalIgnoreCase))
                    value = WebUtility.HtmlDecode(attribute.Groups["value"].Value);
                if (attribute.Groups["name"].Value.Equals("type", StringComparison.OrdinalIgnoreCase))
                    type = attribute.Groups["value"].Value;
            }
            if (name != null && (type?.Equals("hidden", StringComparison.OrdinalIgnoreCase) == true || name == "state"))
                _formFields[name] = value ?? string.Empty;
            if (name == "state" && !string.IsNullOrWhiteSpace(value))
                state = value;
        }
        if (state != null) return (verifier, challenge, state);
        throw new InvalidDataException("Ankama : formulaire sans state (protection WAF ou formulaire modifié).");
    }

    public async Task<AnkamaAccountInfo> GetAccountInfo(string apiKey, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://haapi.ankama.com/json/Ankama/v5/Account/Account");
        request.Headers.Add("apikey", apiKey);
        using var response = await _client.SendAsync(request, ct);
        EnsureNoProtection(response, "la lecture du compte");
        response.EnsureSuccessStatusCode();
        var info = JsonSerializer.Deserialize<AnkamaAccountInfo>(await response.Content.ReadAsStringAsync(ct));
        if (info == null || info.Id <= 0 || string.IsNullOrWhiteSpace(info.Login))
            throw new InvalidDataException("Ankama : informations de compte incomplètes.");
        return info;
    }

    internal static string GenerateCodeVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));
    internal static string CreateCodeChallenge(string verifier) => Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
    internal static string BuildLoginUrl(string challenge) => $"https://auth.ankama.com/login/ankama?code_challenge={challenge}&redirect_uri=zaap://login&client_id=102&direct=true&origin_tracker=https://www.ankama-launcher.com/launcher";
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public async Task<(string accessToken, string refreshToken, bool retry)> LoginStep2(
        string user, string password, string codeVerifier, string codeChallenge, string state, string? awsToken,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(state);
        if (CreateCodeChallenge(codeVerifier) != codeChallenge)
            throw new ArgumentException("Ankama : paramètres PKCE incohérents.");
        if (!string.IsNullOrWhiteSpace(awsToken))
            _cookies.Add(new Cookie("aws-waf-token", awsToken, "/", "auth.ankama.com") { Secure = true });
        var fields = new Dictionary<string, string>(_formFields, StringComparer.Ordinal)
        {
            ["state"] = state,
            ["login"] = user,
            ["password"] = password
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://auth.ankama.com/login/ankama/form")
        {
            Content = new FormUrlEncodedContent(fields)
        };
        AddNavigationHeaders(request, "same-origin");
        request.Headers.Add("Origin", "https://auth.ankama.com");
        request.Headers.Referrer = _formUri;
        using var response = await SendFollowingRedirects(request, ct);
        EnsureNoProtection(response, "la soumission des identifiants");
        var html = await response.Content.ReadAsStringAsync(ct);
        if (IsBanned(html))
            throw new AnkamaBannedException();
        if (html.Contains("The request could not be satisfied", StringComparison.Ordinal))
            return (string.Empty, string.Empty, true);
        response.EnsureSuccessStatusCode();
        var code = GetLoginCode(response.Headers.Location?.ToString());
        if (code == null)
        {
            var match = Regex.Match(WebUtility.HtmlDecode(html), @"zaap://login\?[^""'<>\s]+",
                RegexOptions.None, TimeSpan.FromSeconds(1));
            code = GetLoginCode(match.Value);
        }
        if (string.IsNullOrWhiteSpace(code))
            throw new InvalidDataException("Ankama : connexion refusée ou validation supplémentaire requise (identifiants, 2FA ou Shield).");
        var tokens = await GetTokens(code, codeVerifier, ct);
        return (tokens.accessToken, tokens.refreshToken, false);
    }

    private async Task<(string accessToken, string refreshToken)> GetTokens(string code, string verifier, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://auth.ankama.com/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["client_id"] = "102",
                ["redirect_uri"] = "zaap://login",
                ["code_verifier"] = verifier
            })
        };
        using var response = await _client.SendAsync(request, ct);
        EnsureNoProtection(response, "l'échange OAuth");
        response.EnsureSuccessStatusCode();
        var tokens = JsonSerializer.Deserialize<ZaapLoginResponse>(await response.Content.ReadAsStringAsync(ct));
        if (tokens == null || string.IsNullOrWhiteSpace(tokens.AccessToken) || string.IsNullOrWhiteSpace(tokens.RefreshToken))
            throw new InvalidDataException("Ankama : réponse OAuth sans jetons valides.");
        return (tokens.AccessToken, tokens.RefreshToken);
    }

    private static void EnsureNoProtection(HttpResponseMessage response, string stage)
    {
        if (!response.Headers.TryGetValues("x-amzn-waf-action", out var values)) return;
        var actions = values.SelectMany(x => x.Split(',')).Select(x => x.Trim().ToLowerInvariant()).ToArray();
        var action = actions.Contains("captcha") ? "captcha" : actions.Contains("challenge") ? "challenge" : "unknown";
        throw new AnkamaProtectionException(response.StatusCode, action, stage);
    }

    private static bool IsBanned(string html)
        => WebUtility.HtmlDecode(html).Contains("Votre compte est banni", StringComparison.OrdinalIgnoreCase)
        || WebUtility.HtmlDecode(html).Contains("Votre compte a été banni", StringComparison.OrdinalIgnoreCase)
        || WebUtility.HtmlDecode(html).Contains("Your account has been permanently banned", StringComparison.OrdinalIgnoreCase);

    private static void AddNavigationHeaders(HttpRequestMessage request, string site)
    {
        request.Headers.TryAddWithoutValidation("sec-fetch-dest", "document");
        request.Headers.TryAddWithoutValidation("sec-fetch-mode", "navigate");
        request.Headers.TryAddWithoutValidation("sec-fetch-site", site);
        request.Headers.TryAddWithoutValidation("sec-fetch-user", "?1");
        request.Headers.TryAddWithoutValidation("upgrade-insecure-requests", "1");
        request.Headers.TryAddWithoutValidation("priority", "u=0, i");
    }

    internal static string? GetLoginCode(string? location)
    {
        if (!Uri.TryCreate(location, UriKind.Absolute, out var uri) || uri.Scheme != "zaap" || uri.Host != "login")
            return null;
        foreach (var part in uri.Query.TrimStart('?').Split('&'))
        {
            var pair = part.Split('=', 2);
            if (pair.Length == 2 && pair[0] == "code")
                return Uri.UnescapeDataString(pair[1]);
        }
        return null;
    }

    private async Task<HttpResponseMessage> SendFollowingRedirects(HttpRequestMessage request, CancellationToken ct)
    {
        var current = request;
        try
        {
            for (var hop = 0; hop < 10; hop++)
            {
                var response = await _client.SendAsync(current, ct);
                var location = response.Headers.Location;
                if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308) || location == null)
                    return response;
                var target = location.IsAbsoluteUri ? location : new Uri(current.RequestUri!, location);
                if (target.Scheme == "zaap" && target.Host == "login")
                {
                    response.Headers.Location = target;
                    // The redirect itself is the successful OAuth response.
                    response.StatusCode = HttpStatusCode.OK;
                    return response;
                }
                var status = response.StatusCode;
                response.Dispose();
                if (target.Scheme != "https" || target.Host != "auth.ankama.com" || !target.IsDefaultPort ||
                    ((int)status is 307 or 308 && current.Method != HttpMethod.Get))
                    throw new InvalidDataException("Ankama : redirection inattendue.");
                if (current != request)
                    current.Dispose();
                current = new HttpRequestMessage(HttpMethod.Get, target);
                AddNavigationHeaders(current, "same-origin");
            }
            throw new InvalidDataException("Ankama : trop de redirections.");
        }
        finally
        {
            if (current != request)
                current.Dispose();
        }
    }
}

public sealed class ZaapLoginResponse
{
    [JsonPropertyName("access_token")] public required string AccessToken { get; set; }
    [JsonPropertyName("refresh_token")] public required string RefreshToken { get; set; }
}
