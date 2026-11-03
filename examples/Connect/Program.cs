using Ankama.Connect;

var input = args.Length == 1
    ? args[0]
    : Environment.GetEnvironmentVariable("ANKAMA_CONNECT_ACCOUNT");
if (string.IsNullOrWhiteSpace(input))
{
    Console.Error.WriteLine("Usage: dotnet run --project examples/Connect -- \"[proxy] login:password\"");
    Console.Error.WriteLine("Proxy example: socks5://user:password@host:1080");
    return 2;
}

using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(2));
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

try
{
    var account = ConnectionInput.ParseAccount(input);
    var proxy = account.proxy == null ? null : ConnectionInput.ParseProxy(account.proxy);
    using var ankama = new AnkamaService { Proxy = proxy };
    ankama.Initialize();
    using var aws = new AwsWafTokenClient(proxy);

    var result = await ankama.LoginHttp(
        account.login,
        account.password,
        token => aws.GetTokenPairAsync(token),
        (existingToken, pageHtml, token) => aws.RefreshTokenPairAsync(
            existingToken, pageHtml, token),
        cancellation.Token);

    Console.WriteLine($"Connected to Ankama account {result.info.Id}.");
    return 0;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Connection timed out or was cancelled.");
    return 1;
}
catch (AnkamaBannedException error)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}
catch (AnkamaProtectionException error)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}
catch (Exception error) when (error is HttpRequestException or InvalidDataException or FormatException)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}
