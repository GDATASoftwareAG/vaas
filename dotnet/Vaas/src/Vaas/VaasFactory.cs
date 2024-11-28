using System.Net.Http;
using Vaas.Authentication;

namespace Vaas;

public static class VaasFactory
{
    private static readonly HttpClient HttpClient = new();

    public static IVaas Create(VaasOptions vaasOptions)
    {
        var systemClock = new SystemClock();
        var authenticator = new Authenticator(HttpClient, systemClock, vaasOptions);

        var bearerTokenHandler = new BearerTokenHandler(authenticator);
        bearerTokenHandler.InnerHandler = new HttpClientHandler();
        var httpClient = new HttpClient(bearerTokenHandler);

        return new Vaas(httpClient, authenticator, vaasOptions);
    }
}
