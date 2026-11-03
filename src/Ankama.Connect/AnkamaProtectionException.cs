using System.Net;

namespace Ankama.Connect;

public sealed class AnkamaProtectionException : Exception
{
    public HttpStatusCode StatusCode { get; }
    public string Action { get; }
    public string Stage { get; }

    public AnkamaProtectionException(HttpStatusCode statusCode, string action, string stage)
        : base($"AWS WAF demande {Describe(action)} pendant {stage} (HTTP {(int)statusCode}). Connexion HTTP interrompue.")
    {
        StatusCode = statusCode;
        Action = action;
        Stage = stage;
    }

    private static string Describe(string action) => action switch
    {
        "captcha" => "un CAPTCHA",
        "challenge" => "une vérification du client",
        _ => "une validation supplémentaire"
    };
}
