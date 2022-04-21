using System.Text.Json.Serialization;

namespace Vaas.Messages
{
    public class Message
    {
        [JsonPropertyName("kind")] 
        public string Kind { get; init; } = null!;
    }
}