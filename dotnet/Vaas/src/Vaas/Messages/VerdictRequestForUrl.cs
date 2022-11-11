using System;
using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class VerdictRequestForUrl
{
    [JsonPropertyName("kind")] 
    public string Kind => "VerdictRequestForUrl";

    [JsonPropertyName("url")] 
    public string Url { get; }

    [JsonPropertyName("guid")] 
    public string Guid { get; }

    [JsonPropertyName("session_id")] 
    public string SessionId { get; }

    [JsonPropertyName("use_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseCache { get; init; } = null;
    
    [JsonPropertyName("use_shed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? UseShed { get; init; } = null;
    
    public VerdictRequestForUrl(Uri uri, string sessionId)
    {
        Url = uri.ToString();
        SessionId = sessionId;
        Guid = System.Guid.NewGuid().ToString();
    }
}