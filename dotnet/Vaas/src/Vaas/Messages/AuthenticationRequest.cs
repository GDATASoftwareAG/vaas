using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class AuthenticationRequest
    {
        [JsonPropertyName("kind")] public string Kind = "AuthRequest";

        [JsonPropertyName("token")] public string Token { get; }

        [JsonPropertyName("session_id")] public string? SessionId { get; }

        public AuthenticationRequest(string token, string? sessionId = null)
        {
            Token = token;
            SessionId = sessionId;
        }
    }
}    