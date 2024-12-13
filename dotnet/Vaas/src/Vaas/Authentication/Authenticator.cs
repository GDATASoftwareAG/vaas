using System;
using System.Collections.Generic;
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
    private TokenResponse? _lastResponse;
    private DateTime _validTo;
    private DateTime? _lastRequestTime;

    public Authenticator(HttpClient httpClient, ISystemClock systemClock, VaasOptions options)
    {
        _httpClient = httpClient;
        _systemClock = systemClock;
        _options = options;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _semaphore.WaitAsync(cancellationToken);

            var now = _systemClock.UtcNow;
            if (_lastResponse != null && _validTo.ToUniversalTime() >= now)
                return _lastResponse.AccessToken;

            if (_lastRequestTime != null)
            {
                var timeToWait = _lastRequestTime + TimeSpan.FromSeconds(1) - now;
                if (timeToWait > TimeSpan.Zero)
                {
                    await Task.Delay(timeToWait.Value, cancellationToken);
                }
            }

            _lastRequestTime = now.UtcDateTime;
            _lastResponse = await RequestTokenAsync(cancellationToken);
            var expiresInSeconds =
                _lastResponse.ExpiresInSeconds
                ?? throw new AuthenticationException("Identity provider did not return expires_in");

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
            ErrorResponse? errorResponse;
            var statusCode = (int)response.StatusCode;
            try
            {
                errorResponse = JsonSerializer.Deserialize<ErrorResponse>(stringResponse);
            }
            catch (JsonException e)
            {
                throw new AuthenticationException(
                    $"Identity provider returned status code {statusCode}: {e.Message}"
                );
            }

            if (errorResponse == null)
            {
                throw new AuthenticationException(
                    $"Identity provider returned status code {statusCode}: Empty body"
                );
            }

            throw new AuthenticationException(
                $"Identity provider returned status code {statusCode}: {errorResponse.ErrorDescription ?? errorResponse.Error}"
            );
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
                    new(
                        "client_secret",
                        _options.Credentials.ClientSecret ?? throw new InvalidOperationException()
                    ),
                    new("grant_type", "client_credentials"),
                }
            );
        }

        return new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", _options.Credentials.ClientId),
                new(
                    "username",
                    _options.Credentials.UserName ?? throw new InvalidOperationException()
                ),
                new(
                    "password",
                    _options.Credentials.Password ?? throw new InvalidOperationException()
                ),
                new("grant_type", "password"),
            }
        );
    }

    public void Dispose()
    {
        _semaphore.Dispose();
    }
}
