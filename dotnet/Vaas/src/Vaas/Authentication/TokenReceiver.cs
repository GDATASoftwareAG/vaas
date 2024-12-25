using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

internal class TokenReceiver(
    IAuthenticator authenticator,
    Uri? tokenUrl = null,
    HttpClient? httpClient = null,
    ISystemClock? systemClock = null
) : IAuthenticator, IDisposable
{
    private readonly Uri _tokenUrl =
        tokenUrl
        ?? new Uri("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient();
    private readonly SemaphoreSlim _semaphore = new(1);
    private readonly ISystemClock _systemClock = systemClock ?? new SystemClock();
    private TokenResponse? _lastResponse;
    private DateTime _validTo;
    private DateTime? _lastRequestTime;

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
            response = await _httpClient.PostAsync(_tokenUrl, form, cancellationToken);
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
        return authenticator switch
        {
            ClientCredentialsGrantAuthenticator grantAuthenticator => new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new("client_id", grantAuthenticator.ClientId),
                    new(
                        "client_secret",
                        grantAuthenticator.ClientSecret ?? throw new InvalidOperationException()
                    ),
                    new("grant_type", "client_credentials"),
                }
            ),
            ResourceOwnerPasswordGrantAuthenticator grantAuthenticator => new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new("client_id", grantAuthenticator.ClientId),
                    new(
                        "username",
                        grantAuthenticator.UserName ?? throw new InvalidOperationException()
                    ),
                    new(
                        "password",
                        grantAuthenticator.Password ?? throw new InvalidOperationException()
                    ),
                    new("grant_type", "password"),
                }
            ),
            _ => throw new InvalidOperationException("Unknown authenticator type"),
        };
    }

    public void Dispose()
    {
        _semaphore.Dispose();
    }
}
