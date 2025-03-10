using Vaas;
using Vaas.Authentication;
using Vaas.Options;

namespace VaasExample;

public static class Program
{
    private static string ClientId => Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty;
    private static string ClientIdForResourceOwnerPasswordGrant => Environment.GetEnvironmentVariable("VAAS_CLIENT_ID") ?? "vaas-customer";
    private static string ClientSecret => Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty;
    private static string UserName => Environment.GetEnvironmentVariable("VAAS_USER_NAME") ?? string.Empty;
    private static string Password => Environment.GetEnvironmentVariable("VAAS_PASSWORD") ?? string.Empty;
    private static Uri VaasUrl => new(Environment.GetEnvironmentVariable("VAAS_URL") ??
                                      "wss://gateway.production.vaas.gdatasecurity.de");
    private static Uri TokenUrl => new(Environment.GetEnvironmentVariable("TOKEN_URL") ??
                                       "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");
        
    public static async Task Main(string[] args)
    {
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
        // If you got a username and password from us, you can use the GrantType.Password like this
        // You may use self registration and create a new username and password for the
        // Credentials by yourself like the example above on https://vaas.gdata.de/login
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator(
            ClientIdForResourceOwnerPasswordGrant,
            UserName,
            Password,
            TokenUrl
        );
        // // Else if you got a client id and client secret from us, you should use the GrantType.ClientCredentials like this
        // var authenticator = new ClientCredentialsGrantAuthenticator(
        //     ClientId,
        //     ClientSecret,
        //     TokenUrl
        // );

        var options = new VaasOptions
        {
            UseCache = true,
            UseHashLookup = true,
            VaasUrl = VaasUrl,
            Timeout = TimeSpan.FromSeconds(300)
        };

        return VaasFactory.Create(authenticator, options);
    }
}