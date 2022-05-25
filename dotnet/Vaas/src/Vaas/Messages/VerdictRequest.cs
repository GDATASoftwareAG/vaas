using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class AnalysisRequest
{
    [JsonPropertyName("kind")] 
    public string Kind => "VerdictRequest";

    [JsonPropertyName("sha256")] 
    public string Sha256 { get; }

    [JsonPropertyName("guid")] 
    public string Guid { get; }

    [JsonPropertyName("session_id")] 
    public string SessionId { get; }

    public AnalysisRequest(string sha256, string sessionId)
    {
        Sha256 = sha256;
        SessionId = sessionId;
        Guid = System.Guid.NewGuid().ToString();
    }
}