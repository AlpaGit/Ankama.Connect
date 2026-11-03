using System.Text.Json.Serialization;

namespace Ankama.Connect;

public sealed record AnkamaAccountInfo
{
    [JsonPropertyName("id")] public required int Id { get; init; }

    [JsonPropertyName("uuid")] public required string Uuid { get; init; }

    [JsonPropertyName("type")] public required string Type { get; init; }

    [JsonPropertyName("login")] public required string Login { get; init; }
}
