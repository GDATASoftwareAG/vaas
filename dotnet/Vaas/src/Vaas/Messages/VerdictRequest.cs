using System.Runtime.Intrinsics.Arm;
using System.Text.Json.Serialization;
using System;

namespace Vaas.Messages
{
    public class AnalysisRequest
    {
        [JsonPropertyName("kind")] 
        public string Kind { get; } = "VerdictRequest";
        
        [JsonPropertyName("sha256")] 
        public string Sha256 { get; }

        [JsonPropertyName("guid")] 
        public string Guid { get; }

        [JsonPropertyName("session_id")] 
        public string SessionId { get; }

        public AnalysisRequest(string sha256, string session_id)
        {
            Sha256 = sha256;
            SessionId = session_id;
            Guid = System.Guid.NewGuid().ToString();
        }
    }
}


// Analysis request
// {
//     "kind": "VerdictRequest", // Unique identifier of the message kind
//     "sha256": "...", // SHA256 hash of the file to be analyzed
//     "guid": "...", // Unique identifier of the request
//     "session_id": "...", // Session identifier