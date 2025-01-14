using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class ClientCredentialsGrantAuthenticator : IAuthenticator
{
    private readonly TokenReceiver _tokenReceiver;

    private string ClientId { get; }
    private string ClientSecret { get; }

    public ClientCredentialsGrantAuthenticator(
        string clientId,
        string clientSecret,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    )
    {
        _tokenReceiver = new ClientCredentialsTokenReceiver(
            this,
            tokenUrl,
            httpClient,
            systemClock
        );
        ClientId = clientId;
        ClientSecret = clientSecret;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        return await _tokenReceiver.GetTokenAsync(cancellationToken);
    }

    private class ClientCredentialsTokenReceiver(
        IAuthenticator authenticator,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    ) : TokenReceiver(authenticator, tokenUrl, httpClient, systemClock)
    {
        protected override FormUrlEncodedContent TokenRequestToForm()
        {
            var authenticator = (ClientCredentialsGrantAuthenticator)Authenticator;
            return new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new("client_id", authenticator.ClientId),
                    new(
                        "client_secret",
                        authenticator.ClientSecret ?? throw new InvalidOperationException()
                    ),
                    new("grant_type", "client_credentials"),
                }
            );
        }
    }
}
