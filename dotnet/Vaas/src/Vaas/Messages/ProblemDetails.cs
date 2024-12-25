using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class ProblemDetails
{
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("detail")]
    public string? Detail { get; init; }
}
