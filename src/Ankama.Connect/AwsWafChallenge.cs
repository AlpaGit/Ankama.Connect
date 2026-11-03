using System.Text.RegularExpressions;

namespace Ankama.Connect;

internal sealed record AwsWafChallenge(
    string Input,
    string? Hmac,
    string Region,
    int Difficulty,
    int Memory)
{
    private static readonly Regex Pattern = new(
        @"var (?<object>_0x[0-9a-f]+)=\{\};[\s\S]*?\k<object>\[_0x[0-9a-f]+\(0x[0-9a-f]+\)\]='(?<input>[^']*)',\k<object>\[_0x[0-9a-f]+\(0x[0-9a-f]+\)\]='(?<hmac>[^']*)',\k<object>\[(?:'region'|_0x[0-9a-f]+\(0x[0-9a-f]+\))\]='(?<region>[^']+)';[\s\S]*?parseInt\('(?<difficulty>\d+)'\);[\s\S]*?parseInt\('(?<memory>\d+)'\)",
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
            int.Parse(match.Groups["difficulty"].Value),
            int.Parse(match.Groups["memory"].Value));
    }
}
