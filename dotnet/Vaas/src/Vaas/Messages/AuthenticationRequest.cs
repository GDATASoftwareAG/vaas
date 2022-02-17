using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class AuthenticationRequest
    {
        [JsonPropertyName("kind")]
        public string Kind = "AuthRequest";
        
        [JsonPropertyName("token")]
        public string Token { get; }
        
        [JsonPropertyName("session_id")]
        public string? SessionId { get; }
        
        public AuthenticationRequest(string token, string? sessionid = null)
        {
            Token = token;
            SessionId = sessionid;
        }
        

        // // Authentication request
        // {
        //     "kind": "AuthRequest", // Unique identifier of the message kind
        //     "token": "...", // Authentication token
        //     "session_id": "...", // Optional: session identifier on reconnect
        // }
    }
}