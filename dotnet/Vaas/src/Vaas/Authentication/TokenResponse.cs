using System.Text.Json.Serialization;
using CommunityToolkit.Diagnostics;

namespace Vaas.Authentication;

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; }
 
    public TokenResponse(string accessToken)
    {
        Guard.IsNotNullOrEmpty(accessToken);
        AccessToken = accessToken;
    }
}