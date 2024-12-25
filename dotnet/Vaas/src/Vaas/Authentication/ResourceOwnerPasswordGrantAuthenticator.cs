using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class ResourceOwnerPasswordGrantAuthenticator : IAuthenticator
{
    private readonly TokenReceiver _tokenReceiver;

    public string ClientId { get; }
    public string UserName { get; }
    public string Password { get; }

    public ResourceOwnerPasswordGrantAuthenticator(
        string clientId,
        string userName,
        string password,
        Uri? tokenUrl = null,
        HttpClient? httpClient = null,
        ISystemClock? systemClock = null
    )
    {
        _tokenReceiver = new TokenReceiver(this, tokenUrl, httpClient, systemClock);

        ClientId = clientId;
        UserName = userName;
        Password = password;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        return await _tokenReceiver.GetTokenAsync(cancellationToken);
    }
}
