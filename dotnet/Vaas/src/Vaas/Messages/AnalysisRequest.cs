using System.Runtime.Intrinsics.Arm;
using System.Text.Json.Serialization;
using System;

namespace Vaas.Messages
{
    public class AnalysisRequest
    {
        [JsonPropertyName("kind")] public string Kind = "AnalysisRequest";

        [JsonPropertyName("sha256")] public string Sha256 { get; }

        [JsonPropertyName("guid")] public string Guid { get; }

        [JsonPropertyName("session_id")] public string SessionId { get; }

        public AnalysisRequest(string sha256, string session_id)
        {
            Sha256 = sha256;
            SessionId = session_id;
            Guid = System.Guid.NewGuid().ToString();
        }
    }
}