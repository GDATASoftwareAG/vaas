using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class VerdictResponse
    {
        [JsonPropertyName("kind")] 
        public string Kind { get; init; } = "VerdictResponse";
        
        [JsonPropertyName("sha256")] 
        public string Sha256 { get; init; }

        [JsonPropertyName("guid")] 
        public string Guid { get; init; }

        [JsonPropertyName("verdict")] 
        public Verdict Verdict { get; init; }
        
        [JsonPropertyName("url")] 
        public string? Url { get; init; }
        
        [JsonPropertyName("upload_token")] 
        public string? UploadToken { get; init; }
    }
}
// Analysis response
// {
//     "kind": "VerdictResponse", // Unique identifier of the message kind
//     "sha256": "...", // SHA256 hash of the analyzed file
//     "guid": "...", // Unique identifier of the request
//     "verdict": "Clean", // Verdict of the analysis (Unknown, Clean, Malicious)
//     "url": "...", // Optional: Upload URL for the file in the case of an "Unknown" verdict
//     "upload_token": "...", // Optional: Upload token for the file in the case of an "Unknown" verdict