using System.Text.RegularExpressions;

namespace Ankama.Connect;

internal sealed record AwsWafChallenge(
    string Input,
    string? Hmac,
    string Region,
    string ChallengeType,
    int Difficulty,
    int Memory)
{
    internal const string MemoryChallengeType =
        "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25";

    private static readonly Regex Pattern = new(
        @"var (?<object>_0x[0-9a-f]+)=\{\};[\s\S]*?\k<object>\[_0x[0-9a-f]+\(0x[0-9a-f]+\)\]='(?<input>[^']*)',\k<object>\[_0x[0-9a-f]+\(0x[0-9a-f]+\)\]='(?<hmac>[^']*)',\k<object>\[(?:'region'|_0x[0-9a-f]+\(0x[0-9a-f]+\))\]='(?<region>[^']+)'[;,][\s\S]*?\k<object>\[(?:'challenge_type'|_0x[0-9a-f]+\(0x[0-9a-f]+\))\]='(?<challenge_type>h[0-9a-f]{64})'[;,][\s\S]*?parseInt\('(?<difficulty>\d+)'\);[\s\S]*?parseInt\('(?<memory>\d+)'\)",
        RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(5));

    public static AwsWafChallenge Parse(string script)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(script);

        var match = Pattern.Match(script);
        if (!match.Success)
            throw new InvalidOperationException("AWS WAF : challenge intégré introuvable.");

        return new AwsWafChallenge(
            match.Groups["input"].Value,
            match.Groups["hmac"].Value,
            match.Groups["region"].Value,
            match.Groups["challenge_type"].Value,
            int.Parse(match.Groups["difficulty"].Value),
            int.Parse(match.Groups["memory"].Value));
    }

    public byte[] CreateMpVerifySolutionData() => ChallengeType switch
    {
        MemoryChallengeType => Difficulty switch
        {
            1 => new byte[0x400],
            2 => new byte[0x2800],
            3 => new byte[0x19000],
            4 => new byte[0x100000],
            5 => new byte[0xA00000],
            _ => throw new InvalidOperationException(
                $"AWS WAF : difficulté mp_verify non supportée ({Difficulty}).")
        },
        _ => throw new InvalidOperationException(
            $"AWS WAF : type de challenge non supporté ({ChallengeType}).")
    };
}
