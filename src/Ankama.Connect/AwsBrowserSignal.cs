using System.Reflection;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ankama.Connect;

internal sealed record AwsSignalPayload(
    string Json,
    string Checksum,
    string Encrypted);

internal static class AwsBrowserSignal
{
    private const string ResourceName = "Ankama.Connect.AwsBrowserSignal.gz.b64";
    private static readonly string FingerprintTemplate;
    private static readonly string TelemetryTemplate;
    private static readonly Regex KeyCandidatePattern = new(
        @"[A-Za-z0-9+/]{80,120}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex KeyPattern = new(
        @"^[0-9a-f]{64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly object KeyLock = new();
    private static byte[]? _key;

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

        using var aes = new AesGcm(GetKey(), 16);
        aes.Encrypt(nonce, bytes, ciphertext, tag);

        return Convert.ToBase64String(nonce) + "::" +
               Convert.ToHexString(ciphertext).ToLowerInvariant() +
               Convert.ToHexString(tag).ToLowerInvariant();
    }

    internal static void UseChallengeScript(string challengeScript)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeScript);
        var key = ExtractKey(challengeScript)
            ?? throw new InvalidOperationException("AWS WAF : clé du signal navigateur introuvable.");

        lock (KeyLock)
        {
            _key = key;
        }
    }

    internal static byte[]? ExtractKey(string challengeScript)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeScript);

        foreach (Match candidate in KeyCandidatePattern.Matches(challengeScript))
        {
            var decoded = DecodeObfuscatedBase64(candidate.Value);
            var text = Encoding.ASCII.GetString(decoded);
            if (KeyPattern.IsMatch(text))
                return Convert.FromHexString(text);
        }

        return null;
    }

    private static byte[] GetKey()
    {
        lock (KeyLock)
        {
            return _key ?? throw new InvalidOperationException("AWS WAF : clé du signal navigateur non initialisée.");
        }
    }

    private static byte[] DecodeObfuscatedBase64(string value)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        var bytes = new List<byte>(value.Length * 3 / 4);
        var accumulator = 0;
        var bitCount = 0;

        foreach (var character in value)
        {
            var index = alphabet.IndexOf(character);
            if (index < 0)
                throw new InvalidOperationException("AWS WAF : encodage du signal navigateur invalide.");

            accumulator = (accumulator << 6) | index;
            bitCount += 6;
            if (bitCount < 8)
                continue;

            bitCount -= 8;
            bytes.Add((byte)((accumulator >> bitCount) & 0xff));
        }

        return [.. bytes];
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
