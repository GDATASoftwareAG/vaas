using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class LibMagic
{
    [JsonPropertyName("file_type")]
    public string FileType { get; init; }

    [JsonPropertyName("mime_type")]
    public string MimeType { get; init; }
}