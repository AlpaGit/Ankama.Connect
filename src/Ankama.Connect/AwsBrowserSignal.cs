using System.Reflection;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ankama.Connect;

internal sealed record AwsSignalPayload(
    string Json,
    string Checksum,
    string Encrypted);

internal static class AwsBrowserSignal
{
    private const string ResourceName = "Ankama.Connect.AwsBrowserSignal.gz.b64";
    private static readonly byte[] Key = Convert.FromHexString("6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98");
    private static readonly string FingerprintTemplate;
    private static readonly string TelemetryTemplate;

    static AwsBrowserSignal()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var resource = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("AWS WAF : signal navigateur introuvable.");

        using var reader = new StreamReader(resource);
        var compressed = Convert.FromBase64String(reader.ReadToEnd().Trim());
        using var input = new MemoryStream(compressed);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);

        var document = JsonNode.Parse(Encoding.UTF8.GetString(output.ToArray()))
            ?? throw new InvalidOperationException("AWS WAF : signal navigateur invalide.");

        FingerprintTemplate = document["fingerprint"]?.ToJsonString()
            ?? throw new InvalidOperationException("AWS WAF : empreinte navigateur introuvable.");
        TelemetryTemplate = document["telemetry"]?.ToJsonString()
            ?? throw new InvalidOperationException("AWS WAF : télémétrie navigateur introuvable.");
    }

    public static AwsSignalPayload CreateFingerprint()
        => Create(FingerprintTemplate, 130, 180);

    public static AwsSignalPayload CreateTelemetry()
        => Create(TelemetryTemplate, 1, 2);

    private static AwsSignalPayload Create(string template, int minimumDurationMilliseconds, int maximumDurationMilliseconds)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var payload = JsonNode.Parse(template)
            ?? throw new InvalidOperationException("AWS WAF : signal navigateur invalide.");

        payload["start"] = now;
        payload["end"] = now + Random.Shared.Next(minimumDurationMilliseconds, maximumDurationMilliseconds + 1);
        payload["id"] = Guid.NewGuid().ToString();

        var json = JsonSerializer.Serialize(payload);
        var checksum = AwsCrc32.ComputeChecksum(json);
        return new AwsSignalPayload(json, checksum, Encrypt(checksum + "#" + json));
    }

    private static string Encrypt(string plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[bytes.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(Key, 16);
        aes.Encrypt(nonce, bytes, ciphertext, tag);

        return Convert.ToBase64String(nonce) + "::" +
               Convert.ToHexString(ciphertext).ToLowerInvariant() +
               Convert.ToHexString(tag).ToLowerInvariant();
    }
}

internal static class AwsCrc32
{
    private static readonly uint[] Table = BuildTable();

    public static string ComputeChecksum(string value)
        => Convert.ToHexString(BitConverter.GetBytes(TableCompute(Encoding.UTF8.GetBytes(value)))).ToUpperInvariant();

    private static uint TableCompute(byte[] data)
    {
        var crc = 0xffffffffu;
        foreach (var value in data)
            crc = (crc >> 8) ^ Table[(crc ^ value) & 0xff];
        return crc ^ 0xffffffffu;
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (var index = 0; index < table.Length; index++)
        {
            var crc = (uint)index;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
            table[index] = crc;
        }

        return table;
    }
}
