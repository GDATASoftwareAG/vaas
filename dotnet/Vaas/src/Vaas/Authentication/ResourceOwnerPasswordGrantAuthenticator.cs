using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class ResourceOwnerPasswordGrantAuthenticator : IAuthenticator
{
    private readonly TokenReceiver _tokenReceiver;

    private string ClientId { get; }
    private string UserName { get; }
    private string Password { get; }

    public ResourceOwnerPasswordGrantAuthenticator(
        string clientId,
        string userName,
        string password,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    )
    {
        _tokenReceiver = new ResourceOwnerPasswordTokenReceiver(
            this,
            tokenUrl,
            httpClient,
            systemClock
        );
        ClientId = clientId;
        UserName = userName;
        Password = password;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        return await _tokenReceiver.GetTokenAsync(cancellationToken);
    }

    private class ResourceOwnerPasswordTokenReceiver(
        IAuthenticator authenticator,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    ) : TokenReceiver(authenticator, tokenUrl, httpClient, systemClock)
    {
        protected override FormUrlEncodedContent TokenRequestToForm()
        {
            var authenticator = (ResourceOwnerPasswordGrantAuthenticator)Authenticator;
            return new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new("client_id", authenticator.ClientId),
                    new(
                        "username",
                        authenticator.UserName ?? throw new InvalidOperationException()
                    ),
                    new(
                        "password",
                        authenticator.Password ?? throw new InvalidOperationException()
                    ),
                    new("grant_type", "password"),
                }
            );
        }
    }
}
