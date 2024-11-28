using System.Text.Json.Serialization;
using CommunityToolkit.Diagnostics;

namespace Vaas.Authentication;

public class ErrorResponse
{
    [JsonPropertyName("error")] public required string Error { get; init; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}