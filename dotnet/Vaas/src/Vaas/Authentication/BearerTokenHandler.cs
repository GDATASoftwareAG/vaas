using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public class BearerTokenHandler : DelegatingHandler
{
    private readonly IAuthenticator _authenticator;

    public BearerTokenHandler(IAuthenticator authenticator) => _authenticator = authenticator;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            await _authenticator.GetTokenAsync(cancellationToken)
        );

        return await base.SendAsync(request, cancellationToken);
    }
}
