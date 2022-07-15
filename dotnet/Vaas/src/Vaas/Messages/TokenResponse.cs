using System.Text.Json.Serialization;

namespace Vaas.Messages;

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
}