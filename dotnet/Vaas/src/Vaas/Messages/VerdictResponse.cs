using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class VerdictResponse
    {
        [JsonPropertyName("kind")] 
        public string Kind { get; init; } = "VerdictResponse";

        [JsonPropertyName("sha256")]
        public string? Sha256 { get; init; }

        [JsonPropertyName("guid")] 
        public string? Guid { get; init; }

        [JsonPropertyName("verdict")] 
        public Verdict Verdict { get; init; }
        
        [JsonPropertyName("url")] 
        public string? Url { get; init; } 
        
        [JsonPropertyName("upload_token")] 
        public string? UploadToken { get; init; }

        [MemberNotNullWhen(true, nameof(Sha256), nameof(Guid))]
        public bool IsValid => !string.IsNullOrWhiteSpace(Sha256)
                               && !string.IsNullOrWhiteSpace(Guid);

    }
}