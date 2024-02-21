using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class VerdictRequestForStream
{
    [JsonPropertyName("kind")]
    public string Kind => "VerdictRequestForStream";

    [JsonPropertyName("guid")]
    public string Guid { get; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; }

    [JsonPropertyName("verdict_request_attributes")]
    public Dictionary<string, string>? VerdictRequestAttributes { get; set; }

    [JsonPropertyName("use_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseCache { get; init; }

    [JsonPropertyName("use_hash_lookup")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseHashLookup { get; init; }

    public VerdictRequestForStream(string sessionId)
    {
        SessionId = sessionId;
        Guid = System.Guid.NewGuid().ToString();
    }
}