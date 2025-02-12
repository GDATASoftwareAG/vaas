using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Vaas.Authentication;

public class ResourceOwnerPasswordGrantAuthenticator(
    string clientId,
    string userName,
    string password,
    Uri? tokenEndpoint = null,
    HttpClient? httpClient = null,
    ISystemClock? systemClock = null
) : TokenReceiver(tokenEndpoint, httpClient, systemClock), IAuthenticator
{
    private string ClientId { get; } = clientId;
    private string UserName { get; } = userName;
    private string Password { get; } = password;

    protected override FormUrlEncodedContent TokenRequestToForm()
    {
        return new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", ClientId),
                new("username", UserName ?? throw new InvalidOperationException()),
                new("password", Password ?? throw new InvalidOperationException()),
                new("grant_type", "password"),
            }
        );
    }
}
