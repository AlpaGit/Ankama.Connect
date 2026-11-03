using System.Net;

namespace Ankama.Connect;

public static class ConnectionInput
{
    public static (string login, string password, string? proxy) ParseAccount(string input)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
        input = input.TrimEnd('\r', '\n');
        string? proxy = null;
        var space = input.IndexOf(' ');
        if (space > 0 && input[..space].Contains("://", StringComparison.Ordinal))
        {
            proxy = input[..space];
            input = input[(space + 1)..].TrimStart();
        }
        var colon = input.IndexOf(':');
        if (colon <= 0 || colon == input.Length - 1 || string.IsNullOrWhiteSpace(input[..colon]))
            throw new FormatException("Compte attendu au format login:mot_de_passe.");
        return (input[..colon].Trim(), input[(colon + 1)..], proxy);
    }

    public static WebProxy ParseProxy(string value)
    {
        // Accept standard scheme://user:password@host:port and the historical
        // scheme://host:port@user:password format used by proxies.txt.
        var separator = value.IndexOf("://", StringComparison.Ordinal);
        if (separator < 1)
            throw new FormatException("Proxy attendu avec un protocole (socks5://, http://...).");
        var scheme = value[..separator].ToLowerInvariant();
        if (scheme is not ("socks5" or "socks4" or "socks4a" or "http" or "https"))
            throw new FormatException("Protocole de proxy non pris en charge.");
        var authority = value[(separator + 3)..];
        var at = authority.IndexOf('@');
        if (at >= 0 && Uri.TryCreate($"{scheme}://{authority[..at]}", UriKind.Absolute, out var legacy) &&
            legacy.Port > 0 && string.IsNullOrEmpty(legacy.UserInfo) &&
            (legacy.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6 || legacy.Host.Contains('.')))
        {
            var credentials = authority[(at + 1)..].Split(':', 2);
            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]))
                throw new FormatException("Identifiants du proxy incomplets.");
            return new WebProxy(legacy) { Credentials = new NetworkCredential(credentials[0], credentials[1]) };
        }
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Port is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(uri.Host) || uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            throw new FormatException("Adresse ou port du proxy invalide.");
        var proxy = new WebProxy(new UriBuilder(uri) { UserName = "", Password = "" }.Uri);
        if (uri.UserInfo.Length > 0)
        {
            var credentials = uri.UserInfo.Split(':', 2);
            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]))
                throw new FormatException("Identifiants du proxy incomplets.");
            proxy.Credentials = new NetworkCredential(Uri.UnescapeDataString(credentials[0]), Uri.UnescapeDataString(credentials[1]));
        }
        return proxy;
    }
}
