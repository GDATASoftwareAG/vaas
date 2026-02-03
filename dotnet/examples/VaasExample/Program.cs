using Vaas;
using Vaas.Authentication;
using Vaas.Options;

namespace VaasExample;

public static class Program
{
    public static async Task Main(string[] args)
    {
        DotNetEnv.Env.TraversePath().Load();
        if (args.Contains("UrlScan"))
            await UrlScan();
        if (args.Contains("FileScan"))
            await FileScan();
        if (args.Contains("HashsumScan"))
            await HashsumScan();
    }

    private static async Task FileScan()
    {
        var vaas = CreateVaas();
        var file = Environment.GetEnvironmentVariable("SCAN_PATH") ?? string.Empty;
        var verdict = await vaas.ForFileAsync(file, CancellationToken.None);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }

    private static async Task HashsumScan()
    {
        var vaas = CreateVaas();
        var verdict = await vaas.ForSha256Async(new ChecksumSha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"), CancellationToken.None);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }

    private static async Task UrlScan()
    {
        var vaas = CreateVaas();

        var uri = new Uri("https://secure.eicar.org/eicar.com.txt");
        var verdict = await vaas.ForUrlAsync(uri, CancellationToken.None);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }

    private static IVaas CreateVaas()
    {
        var clientId = Environment.GetEnvironmentVariable("CLIENT_ID");
        var clientIdForResourceOwnerPasswordGrant = Environment.GetEnvironmentVariable("VAAS_CLIENT_ID") ?? "vaas-customer";
        var clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
        var userName = Environment.GetEnvironmentVariable("VAAS_USER_NAME");
        var password = Environment.GetEnvironmentVariable("VAAS_PASSWORD");
        var vaasUrl = new Uri(Environment.GetEnvironmentVariable("VAAS_URL") ??
                                          "https://gateway.production.vaas.gdatasecurity.de");
        var tokenUrl = new Uri(Environment.GetEnvironmentVariable("TOKEN_URL") ??
                                           "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");

        IAuthenticator authenticator;
        if (userName is not null)
        {
            if (password is null)
                throw new ArgumentNullException("VAAS_PASSWORD", "Password must be set when using Resource Owner Password Grant");
            // If you got a username and password from us, you can use the GrantType.Password like this
            // You may use self registration and create a new username and password for the
            // Credentials by yourself like the example above on https://vaas.gdata.de/login
            authenticator = new ResourceOwnerPasswordGrantAuthenticator(
                clientIdForResourceOwnerPasswordGrant,
                userName,
                password,
                tokenUrl
            );

        }
        else
        {
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                throw new ArgumentNullException("CLIENT_ID or CLIENT_SECRET", "CLIENT_ID and CLIENT_SECRET must be set when using Client Credentials Grant");
            }

            // Else if you got a client id and client secret from us, you should use the GrantType.ClientCredentials like this
            authenticator = new ClientCredentialsGrantAuthenticator(
                clientId,
                clientSecret,
                tokenUrl
            );
        }

        var options = new VaasOptions
        {
            UseCache = true,
            UseHashLookup = true,
            VaasUrl = vaasUrl,
            Timeout = TimeSpan.FromSeconds(300)
        };

        return VaasFactory.Create(authenticator, options);
    }
}