using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class Authenticator : IAuthenticator, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ISystemClock _systemClock;
    private readonly VaasOptions _options;
    private readonly SemaphoreSlim _semaphore = new(1);
    private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler = new();
    private TokenResponse? _lastResponse;
    private DateTime _validTo;

    public Authenticator(HttpClient httpClient, ISystemClock systemClock, VaasOptions options)
    {
        _httpClient = httpClient;
        _systemClock = systemClock;
        _options = options;
    }

    /// <exception cref="AuthenticationException"></exception>
    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _semaphore.WaitAsync(cancellationToken);

            if (_lastResponse != null && _validTo.ToUniversalTime() >= _systemClock.UtcNow)
                return _lastResponse.AccessToken;

            _lastResponse = await RequestTokenAsync(cancellationToken);
            var expiresInSeconds = _lastResponse.ExpiresInSeconds ??
                                   throw new AuthenticationException("Identity provider did not return expires_in");

            _validTo = _systemClock.UtcNow.Add(TimeSpan.FromSeconds(expiresInSeconds)).UtcDateTime;
            return _lastResponse.AccessToken;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task<TokenResponse> RequestTokenAsync(CancellationToken cancellationToken)
    {
        var form = TokenRequestToForm();
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.PostAsync(_options.TokenUrl, form, cancellationToken);
        }
        catch (Exception ex)
        {
            throw new AuthenticationException("Failed to request token", ex);
        }

        var stringResponse = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var statusCode = (int)response.StatusCode;
            try
            {
                var errorResponse = JsonSerializer.Deserialize<ErrorResponse>(stringResponse) ??
                                    throw new JsonException("empty response");
                throw new AuthenticationException(
                    $"Identity provider returned status code {statusCode} {errorResponse.Error} {errorResponse.ErrorDescription ?? ""}");
            }
            catch (JsonException)
            {
                throw new AuthenticationException($"Identity provider returned status code: {statusCode}");
            }
        }

        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(stringResponse);
        if (tokenResponse == null)
            throw new AuthenticationException("Access token is null");
        return tokenResponse;
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

    public void Dispose()
    {
        _semaphore.Dispose();
    }
}