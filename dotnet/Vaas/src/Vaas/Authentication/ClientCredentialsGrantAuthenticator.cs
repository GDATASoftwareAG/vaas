using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Vaas.Authentication;

public class ClientCredentialsGrantAuthenticator(
    string clientId,
    string clientSecret,
    Uri? tokenEndpoint = null,
    HttpClient? httpClient = null,
    ISystemClock? systemClock = null
) : TokenReceiver(tokenEndpoint, httpClient, systemClock), IAuthenticator
{
    private string ClientId { get; } = clientId;
    private string ClientSecret { get; } = clientSecret;

    protected override FormUrlEncodedContent TokenRequestToForm()
    {
        return new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", ClientId),
                new("client_secret", ClientSecret ?? throw new InvalidOperationException()),
                new("grant_type", "client_credentials"),
            }
        );
    }
}
