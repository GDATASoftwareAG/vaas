using System.Diagnostics.CodeAnalysis;
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
        public string? SessionId { get; init; }

        [JsonPropertyName("text")] 
        public string? Text { get; init; }

        [MemberNotNullWhen(true, nameof(SessionId), nameof(Text))]
        public bool IsValid => !string.IsNullOrWhiteSpace(SessionId)
                               && !string.IsNullOrWhiteSpace(Text);
    }
}