using System;
using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class ProblemDetails
{
    [JsonPropertyName("type")] public string? Type { get; set; }

    [JsonPropertyName("detail")] public string? Detail { get; set; }
}

public class WebSocketErrorMessage : Message
{
    [JsonPropertyName("type")] public string Type { get; }

    [JsonPropertyName("problem_details")] public ProblemDetails? ProblemDetails { get; init; }

    [JsonPropertyName("request_id")] public string? RequestId { get; set; }
}