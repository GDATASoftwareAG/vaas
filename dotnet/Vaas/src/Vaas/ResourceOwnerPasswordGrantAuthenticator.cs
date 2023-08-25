using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Vaas.Messages;

namespace Vaas;

public class ResourceOwnerPasswordGrantAuthenticator
{
    private readonly string _clientId;
    private readonly string _userName;
    private readonly string _password;
    private readonly Uri _tokenEndpoint;
    private readonly HttpClient _httpClient = new();

    public ResourceOwnerPasswordGrantAuthenticator(string clientId, string userName, string password, Uri tokenEndpoint)
    {
        _clientId = clientId;
        _userName = userName;
        _password = password;
        _tokenEndpoint = tokenEndpoint;
    }

    public async Task<string> GetToken()
    {
        var response = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", _clientId),
                new("username", _userName),
                new("password", _password),
                new("grant_type", "password")
            }));
        var stringResponse = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(stringResponse);
        if (tokenResponse == null)
            throw new JsonException("Access token is null");
        return tokenResponse.AccessToken;
    }
}