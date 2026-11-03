using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ankama.Connect;

internal sealed record AwsSignalPayload(
    string Json,
    string Checksum,
    string Encrypted,
    AwsMetric[] Metrics);

internal sealed record AwsMetric(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("value")] double Value,
    [property: JsonPropertyName("unit")] string Unit);

internal static class AwsBrowserSignal
{
    private static readonly Regex KeyCandidatePattern = new(
        @"[A-Za-z0-9+/]{80,120}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex KeyPattern = new(
        @"^[0-9a-f]{64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex VersionPattern = new(
        @"(?<![\w.])\d+\.\d+\.\d+(?![\w.])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex MathConstantPattern = new(
        @"0x[0-9a-f]{200,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] Plugins =
    [
        "PDF Viewer",
        "Chrome PDF Viewer",
        "Chromium PDF Viewer",
        "Microsoft Edge PDF Viewer",
        "WebKit built-in PDF"
    ];

    private static readonly string[] GpuExtensions =
    [
        "ANGLE_instanced_arrays",
        "EXT_blend_minmax",
        "EXT_clip_control",
        "EXT_color_buffer_half_float",
        "EXT_depth_clamp",
        "EXT_disjoint_timer_query",
        "EXT_float_blend",
        "EXT_frag_depth",
        "EXT_polygon_offset_clamp",
        "EXT_shader_texture_lod",
        "EXT_texture_compression_bptc",
        "EXT_texture_compression_rgtc",
        "EXT_texture_filter_anisotropic",
        "EXT_texture_mirror_clamp_to_edge",
        "EXT_sRGB",
        "KHR_parallel_shader_compile",
        "OES_element_index_uint",
        "OES_fbo_render_mipmap",
        "OES_standard_derivatives",
        "OES_texture_float",
        "OES_texture_float_linear",
        "OES_texture_half_float",
        "OES_texture_half_float_linear",
        "OES_vertex_array_object",
        "WEBGL_blend_func_extended",
        "WEBGL_color_buffer_float",
        "WEBGL_compressed_texture_s3tc",
        "WEBGL_compressed_texture_s3tc_srgb",
        "WEBGL_debug_renderer_info",
        "WEBGL_debug_shaders",
        "WEBGL_depth_texture",
        "WEBGL_draw_buffers",
        "WEBGL_lose_context",
        "WEBGL_multi_draw",
        "WEBGL_polygon_mode"
    ];

    private static readonly BrowserProfile[] BrowserProfiles =
    [
        new(
            "Google Inc. (NVIDIA)",
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti SUPER (0x00002705) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "1366-768-768-24-*-*-*"),
        new(
            "Google Inc. (Intel)",
            "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00009bc8) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "1920-1080-1040-24-*-*-*"),
        new(
            "Google Inc. (AMD)",
            "ANGLE (AMD, AMD Radeon RX 6600 (0x000073ff) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "2560-1440-1400-24-*-*-*")
    ];

    private static readonly object StateLock = new();
    private static byte[]? _key;
    private static string? _signalVersion;
    private static double _mathConstant;

    public static AwsSignalPayload CreateFingerprint()
        => CreateFingerprint(Random.Shared);

    internal static AwsSignalPayload CreateFingerprint(Random random)
    {
        var canvasDuration = random.Next(120, 151);
        return Create(
            CreateFingerprintTemplate(random, canvasDuration),
            random,
            130,
            180,
            CreateFingerprintMetrics(random, canvasDuration));
    }

    public static AwsSignalPayload CreateTelemetry()
        => CreateTelemetry(Random.Shared, false);

    internal static AwsSignalPayload CreateTelemetry(Random random)
        => CreateTelemetry(random, false);

    internal static AwsSignalPayload CreateTelemetry(Random random, bool second)
    {
        return Create(
            CreateTelemetryTemplate(random),
            random,
            1,
            2,
            CreateTelemetryMetrics(random, second),
            (payload, now) =>
            {
                payload["ciba"]!["start"] = now - random.Next(0, 4);
                payload["ciba"]!["events"] = new JsonArray(new JsonObject
                {
                    ["type"] = "i",
                    ["time"] = random.Next(1, 5),
                    ["startTime"] = 0
                });
            });
    }

    internal static AwsMetric[] CreateFingerprintMetrics(Random random, int canvasDuration)
    {
        var totalDuration = canvasDuration + random.Next(25, 46);
        var browserDuration = canvasDuration + random.Next(20, 41);
        var overallDuration = totalDuration + random.Next(90, 141);
        return
        [
            new("2", 1, "2"),
            new("100", 0, "2"),
            new("102", 1, "2"),
            new("111", canvasDuration, "2"),
            new("103", 6, "2"),
            new("104", 0, "2"),
            new("105", 0, "2"),
            new("106", 0, "2"),
            new("107", 0, "2"),
            new("110", 0, "2"),
            new("108", 1, "2"),
            new("101", 0, "2"),
            new("115", 1, "2"),
            new("114", 13, "2"),
            new("112", 0, "2"),
            new("3", RandomRange(random, 3.2, 3.6), "2"),
            new("7", 0, "4"),
            new("1", totalDuration, "2"),
            new("4", random.Next(2, 5), "2"),
            new("5", RandomRange(random, 0.4, 0.6), "2"),
            new("6", browserDuration, "2"),
            new("0", overallDuration, "2"),
            new("8", random.Next(1, 3), "4")
        ];
    }

    internal static AwsMetric[] CreateTelemetryMetrics(Random random, bool second)
    {
        var scriptDuration = second ? RandomRange(random, 0.04, 0.08) : RandomRange(random, 0.08, 0.14);
        var renderDuration = second ? RandomRange(random, 0.4, 0.7) : RandomRange(random, 0.7, 1.0);
        var totalDuration = second ? RandomRange(random, 0.7, 1.1) : RandomRange(random, 2.5, 3.8);
        return
        [
            new("12", scriptDuration, "2"),
            new("200", 0, "2"),
            new("201", 0, "2"),
            new("13", renderDuration, "2"),
            new("10", 0, "4"),
            new("9", 0, "4"),
            new("11", totalDuration, "2")
        ];
    }

    private static double RandomRange(Random random, double minimum, double maximum)
        => Math.Round(minimum + random.NextDouble() * (maximum - minimum), 12);

    internal static void UseChallengeScript(string challengeScript)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeScript);
        var key = ExtractKey(challengeScript)
            ?? throw new InvalidOperationException("AWS WAF : clé du signal navigateur introuvable.");
        var signalVersion = ExtractSignalVersion(challengeScript)
            ?? throw new InvalidOperationException("AWS WAF : version du signal navigateur introuvable.");
        var mathConstant = ExtractMathConstant(challengeScript)
            ?? throw new InvalidOperationException("AWS WAF : constante mathématique du signal navigateur introuvable.");

        lock (StateLock)
        {
            _key = key;
            _signalVersion = signalVersion;
            _mathConstant = mathConstant;
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

    internal static string? ExtractSignalVersion(string challengeScript)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeScript);

        Version? best = null;
        foreach (Match match in VersionPattern.Matches(challengeScript))
        {
            if (Version.TryParse(match.Value, out var version) && (best is null || version > best))
                best = version;
        }

        return best?.ToString();
    }

    internal static double? ExtractMathConstant(string challengeScript)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeScript);

        var match = MathConstantPattern.Match(challengeScript);
        if (!match.Success)
            return null;

        var value = BigInteger.Parse(match.Value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return -(double)value;
    }

    private static JsonObject CreateFingerprintTemplate(Random random, int canvasDuration)
    {
        var profile = BrowserProfiles[random.Next(BrowserProfiles.Length)];
        var plugins = new JsonArray();
        foreach (var plugin in Plugins)
        {
            plugins.Add(new JsonObject
            {
                ["name"] = plugin,
                ["str"] = plugin + " "
            });
        }

        return new JsonObject
        {
            ["metrics"] = CreateCollectorMetrics(random, canvasDuration),
            ["start"] = 0,
            ["flashVersion"] = null,
            ["plugins"] = plugins,
            ["dupedPlugins"] = string.Join(" ", Plugins) + " ||" + profile.ScreenInfo,
            ["screenInfo"] = profile.ScreenInfo,
            ["capabilities"] = new JsonObject
            {
                ["css"] = new JsonObject
                {
                    ["textShadow"] = 1,
                    ["WebkitTextStroke"] = 1,
                    ["boxShadow"] = 1,
                    ["borderRadius"] = 1,
                    ["borderImage"] = 1,
                    ["opacity"] = 1,
                    ["transform"] = 1,
                    ["transition"] = 1
                },
                ["js"] = new JsonObject
                {
                    ["audio"] = true,
                    ["geolocation"] = true,
                    ["localStorage"] = "supported",
                    ["touch"] = false,
                    ["video"] = true,
                    ["webWorker"] = true
                },
                ["elapsed"] = 0
            },
            ["canvas"] = AwsCanvasFingerprint.Create(CreateMath()),
            ["gpu"] = new JsonObject
            {
                ["vendor"] = profile.GpuVendor,
                ["model"] = profile.GpuModel,
                ["extensions"] = CreateStringArray(GpuExtensions)
            },
            ["dnt"] = null,
            ["math"] = CreateMath(),
            ["crypto"] = new JsonObject
            {
                ["crypto"] = 1,
                ["subtle"] = 1,
                ["encrypt"] = true,
                ["decrypt"] = true,
                ["wrapKey"] = true,
                ["unwrapKey"] = true,
                ["sign"] = true,
                ["verify"] = true,
                ["digest"] = true,
                ["deriveBits"] = true,
                ["deriveKey"] = true,
                ["getRandomValues"] = true,
                ["randomUUID"] = true
            },
            ["automation"] = new JsonObject
            {
                ["wd"] = new JsonObject
                {
                    ["properties"] = new JsonObject
                    {
                        ["document"] = new JsonArray(),
                        ["window"] = new JsonArray(),
                        ["navigator"] = new JsonArray()
                    }
                },
                ["phantom"] = new JsonObject
                {
                    ["properties"] = new JsonObject { ["window"] = new JsonArray() }
                }
            },
            ["referrer"] = "",
            ["userAgent"] = AwsBrowserConstants.UserAgent,
            ["location"] = AwsBrowserConstants.LoginLocation,
            ["webDriver"] = false,
            ["be"] = new JsonObject { ["si"] = false },
            ["cdp"] = new JsonObject
            {
                ["pw"] = new JsonArray(),
                ["pp"] = new JsonArray(),
                ["pf"] = "na",
                ["cd"] = new JsonArray(),
                ["xb"] = new JsonArray()
            },
            ["stealth"] = new JsonObject
            {
                ["t1"] = 0,
                ["t2"] = 0,
                ["i"] = 1,
                ["mte"] = 0,
                ["mtd"] = false
            },
            ["formDetected"] = false,
            ["numForms"] = 0,
            ["numFormElements"] = 0,
            ["end"] = 0,
            ["errors"] = new JsonArray(),
            ["version"] = GetSignalVersion(),
            ["id"] = ""
        };
    }

    private static JsonObject CreateTelemetryTemplate(Random random)
    {
        return new JsonObject
        {
            ["metrics"] = new JsonObject { ["ges"] = 0, ["input"] = 0 },
            ["start"] = 0,
            ["ciba"] = new JsonObject
            {
                ["start"] = 0,
                ["events"] = new JsonArray()
            },
            ["end"] = 0,
            ["form"] = new JsonObject
            {
                ["ankama-login"] = CreateFormFieldTelemetry(random),
                ["ankama-password"] = CreateFormFieldTelemetry(random)
            },
            ["errors"] = new JsonArray(),
            ["tVersion"] = GetSignalVersion(),
            ["id"] = ""
        };
    }

    private static JsonObject CreateFormFieldTelemetry(Random random)
    {
        var width = 275 + random.Next(0, 256) * 0.0625;
        return new JsonObject
        {
            ["clicks"] = 0,
            ["touches"] = 0,
            ["keyPresses"] = 0,
            ["cuts"] = 0,
            ["copies"] = 0,
            ["pastes"] = 0,
            ["keyPressTimeIntervals"] = new JsonArray(),
            ["mouseClickPositions"] = new JsonArray(),
            ["keyCycles"] = new JsonArray(),
            ["mouseCycles"] = new JsonArray(),
            ["touchCycles"] = new JsonArray(),
            ["width"] = Math.Round(width, 6),
            ["height"] = 48,
            ["totalFocusTime"] = 0,
            ["prefilled"] = false
        };
    }

    private static JsonObject CreateCollectorMetrics(Random random, int canvasDuration)
        => new()
        {
            ["fp2"] = 1,
            ["capabilities"] = 0,
            ["canvas"] = canvasDuration,
            ["gpu"] = random.Next(5, 10),
            ["dnt"] = 1,
            ["math"] = 0,
            ["screen"] = 0,
            ["navigator"] = 0,
            ["subtle"] = 0,
            ["auto"] = 0,
            ["browser"] = 1,
            ["be"] = 0,
            ["cdp"] = random.Next(10, 17),
            ["stealth"] = 1,
            ["formdetector"] = 0
        };

    private static JsonObject CreateMath()
    {
        var angle = GetMathConstant();
        return new JsonObject
        {
            ["tan"] = Math.Tan(angle).ToString("R", CultureInfo.InvariantCulture),
            ["sin"] = Math.Sin(angle).ToString("R", CultureInfo.InvariantCulture),
            ["cos"] = Math.Cos(angle).ToString("R", CultureInfo.InvariantCulture)
        };
    }

    private static AwsSignalPayload Create(
        JsonObject payload,
        Random random,
        int minimumDurationMilliseconds,
        int maximumDurationMilliseconds,
        AwsMetric[] metrics,
        Action<JsonObject, long>? afterTimestamps = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        payload["start"] = now;
        payload["end"] = now + random.Next(minimumDurationMilliseconds, maximumDurationMilliseconds + 1);
        payload["id"] = Guid.NewGuid().ToString();
        afterTimestamps?.Invoke(payload, now);

        var json = JsonSerializer.Serialize(payload);
        var checksum = AwsCrc32.ComputeChecksum(json);
        return new AwsSignalPayload(json, checksum, Encrypt(checksum + "#" + json), metrics);
    }

    private static byte[] GetKey()
    {
        lock (StateLock)
        {
            return _key ?? throw new InvalidOperationException("AWS WAF : clé du signal navigateur non initialisée.");
        }
    }

    private static string GetSignalVersion()
    {
        lock (StateLock)
        {
            return _signalVersion ?? throw new InvalidOperationException("AWS WAF : version du signal navigateur non initialisée.");
        }
    }

    private static double GetMathConstant()
    {
        lock (StateLock)
        {
            return _mathConstant;
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

    private static JsonArray CreateStringArray(IEnumerable<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
            array.Add(value);
        return array;
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

    private sealed record BrowserProfile(
        string GpuVendor,
        string GpuModel,
        string ScreenInfo);
}

internal static class AwsCrc32
{
    private static readonly uint[] Table = BuildTable();

    public static string ComputeChecksum(string value)
        => Convert.ToHexString(BitConverter.GetBytes(TableCompute(Encoding.UTF8.GetBytes(value)))).ToUpperInvariant();

    internal static uint ComputeUInt32(string value)
        => TableCompute(Encoding.UTF8.GetBytes(value));

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
