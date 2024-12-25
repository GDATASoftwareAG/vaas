using System.Net.Http;
using Vaas.Authentication;
using Vaas.Options;

namespace Vaas;

public static class VaasFactory
{
    public static IVaas Create(
        IAuthenticator authenticator,
        VaasOptions? vaasOptions = null,
        HttpClient? httpClient = null
    )
    {
        return new Vaas(
            authenticator,
            vaasOptions ?? new VaasOptions(),
            httpClient ?? new HttpClient()
        );
    }
}
