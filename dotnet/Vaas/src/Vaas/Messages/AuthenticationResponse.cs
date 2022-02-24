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
        public string SessionId { get; init; }
        
        [JsonPropertyName("text")] 
        public string Text { get; init; }
        
        
        // Authentication response
        // {
        //     "kind": "AuthResponse", // Unique identifier of the message kind
        //     "success": true, // True, if the authentication was successful
        //     "session_id": "...", // Session identifier
        //     "text": "...", // Message for successful authentication
        // }
        // ```
    }
}