using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class AuthenticationResponse
    {
        [JsonPropertyName("kind")] 
        public string Kind = "AuthResponse";
        
        [JsonPropertyName("success")] 
        public bool Success { get; init; }

        [JsonPropertyName("session_id")] 
        public string SessionId { get; init; } = null!;

        [JsonPropertyName("text")] 
        public string Text { get; init; } = null!;
    }
}