using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class VerdictResponse
    {
        [JsonPropertyName("kind")] 
        public string Kind { get; init; } = "VerdictResponse";

        [JsonPropertyName("sha256")] 
        public string Sha256 { get; init; } = null!;

        [JsonPropertyName("guid")] 
        public string Guid { get; init; } = null!;

        [JsonPropertyName("verdict")] 
        public Verdict Verdict { get; init; }
        
        [JsonPropertyName("url")] 
        public string? Url { get; init; }
        
        [JsonPropertyName("upload_token")] 
        public string? UploadToken { get; init; }
    }
}