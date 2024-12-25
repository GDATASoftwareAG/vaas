using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class ClientCredentialsGrantAuthenticator : IAuthenticator
{
    private readonly TokenReceiver _tokenReceiver;

    public string ClientId { get; }
    public string ClientSecret { get; }

    public ClientCredentialsGrantAuthenticator(
        string clientId,
        string clientSecret,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    )
    {
        _tokenReceiver = new TokenReceiver(this, tokenUrl, httpClient, systemClock);

        ClientId = clientId;
        ClientSecret = clientSecret;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        return await _tokenReceiver.GetTokenAsync(cancellationToken);
    }
}
