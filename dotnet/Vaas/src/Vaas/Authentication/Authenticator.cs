using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Vaas.Messages;

namespace Vaas.Authentication;

public class Authenticator : IAuthenticator
{
    private readonly HttpClient _httpClient;
    private readonly VaasOptions _options;

    public Authenticator(HttpClient httpClient, VaasOptions options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        var form = TokenRequestToForm();
        var response = await _httpClient.PostAsync(_options.TokenUrl, form, cancellationToken);
        response.EnsureSuccessStatusCode();
        var stringResponse = await response.Content.ReadAsStringAsync(cancellationToken);
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(stringResponse);
        if (tokenResponse == null)
            throw new JsonException("Access token is null");
        return tokenResponse.AccessToken;
    }

    private FormUrlEncodedContent TokenRequestToForm()
    {
        if (_options.Credentials.GrantType == GrantType.ClientCredentials)
        {
            return new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new("client_id", _options.Credentials.ClientId),
                    new("client_secret", _options.Credentials.ClientSecret ?? throw new InvalidOperationException()),
                    new("grant_type", "client_credentials")
                }
            );
        }
        
        return new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", _options.Credentials.ClientId),
                new("username", _options.Credentials.UserName ?? throw new InvalidOperationException()),
                new("password", _options.Credentials.Password ?? throw new InvalidOperationException()),
                new("grant_type", "password")
            });
    }

    public Task<string> RefreshTokenAsync(CancellationToken cancellationToken)
    {
        throw new System.NotImplementedException();
    }
}
