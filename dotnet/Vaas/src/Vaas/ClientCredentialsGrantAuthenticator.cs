using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Vaas.Messages;

namespace Vaas;

public class ClientCredentialsGrantAuthenticator : IAuthenticator
{
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly Uri _tokenEndpoint;
    private readonly HttpClient _httpClient = new();

    public ClientCredentialsGrantAuthenticator(string clientId, string clientSecret, Uri tokenEndpoint)
    {
        _clientId = clientId;
        _clientSecret = clientSecret;
        _tokenEndpoint = tokenEndpoint;
    }

    public async Task<string> GetToken()
    {
        var response = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", _clientId),
                new("client_secret", _clientSecret),
                new("grant_type", "client_credentials")
            }));
        var stringResponse = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(stringResponse);
        if (tokenResponse == null)
            throw new JsonException("Access token is null");
        return tokenResponse.AccessToken;
    }
}