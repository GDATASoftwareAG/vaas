using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class VerdictRequest
{
    [JsonPropertyName("kind")]
    public string Kind => "VerdictRequest";

    [JsonPropertyName("sha256")]
    public string Sha256 { get; }

    [JsonPropertyName("guid")]
    public string Guid { get; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; }

    [JsonPropertyName("verdict_request_attributes")]
    public Dictionary<string, string>? VerdictRequestAttributes { get; set; }

    [JsonPropertyName("use_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseCache { get; init; }

    [JsonPropertyName("use_shed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseShed { get; init; }

    public VerdictRequest(string sha256, string sessionId)
    {
        Sha256 = sha256;
        SessionId = sessionId;
        Guid = System.Guid.NewGuid().ToString();
    }
}