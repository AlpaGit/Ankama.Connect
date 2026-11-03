# Ankama.Connect

Minimal .NET library and console example for HTTP-only Ankama authentication.

Features:

- OAuth/PKCE account login
- AWS WAF token acquisition and refresh
- browser fingerprint and telemetry generated without a captured template
- banned-account detection
- HTTP, HTTPS, SOCKS4 and SOCKS5 proxy support

```powershell
dotnet run --project examples/Connect -- "socks5://proxyuser:proxypass@proxyhost:1080 login:password"
```

The example also accepts the historical proxy format:

```powershell
dotnet run --project examples/Connect -- "http://proxyhost:1080@proxyuser:proxypass login:password"
```

Run the tests with:

```powershell
dotnet test Ankama.Connect.slnx
```
