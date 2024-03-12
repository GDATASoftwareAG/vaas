using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class LibMagic
{
    [JsonPropertyName("fileType")]
    public string FileType { get; init; }
    
    [JsonPropertyName("mimeType")]
    public string MimeType { get; init; }
}