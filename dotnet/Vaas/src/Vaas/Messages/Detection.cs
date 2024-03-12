using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class Detection
{
    [JsonPropertyName("engine")]
    public int? Engine { get; init; }
    
    [JsonPropertyName("fileName")]
    public string FileName { get; init; }
    
    [JsonPropertyName("virus")]
    public string Virus { get; init; }
}