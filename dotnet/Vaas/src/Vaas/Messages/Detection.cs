using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class Detection
{
    [JsonPropertyName("engine")]
    public int? Engine { get; init; }

    [JsonPropertyName("file_name")]
    public string FileName { get; init; }

    [JsonPropertyName("virus")]
    public string Virus { get; init; }
}