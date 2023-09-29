using Vaas;

namespace VaasExample;

public static class Program
{
    private static string ClientId => Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty;
    private static string ClientIdForResourceOwnerPasswordGrant => Environment.GetEnvironmentVariable("VAAS_CLIENT_ID") ?? string.Empty;
    private static string ClientSecret => Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty;
    private static string UserName => Environment.GetEnvironmentVariable("VAAS_USER_NAME") ?? string.Empty;
    private static string Password => Environment.GetEnvironmentVariable("VAAS_PASSWORD") ?? string.Empty;
    private static Uri VaasUrl => new Uri(Environment.GetEnvironmentVariable("VAAS_URL") ??
                                          "wss://gateway.production.vaas.gdatasecurity.de");
    private static Uri TokenUrl => new Uri(Environment.GetEnvironmentVariable("TOKEN_URL") ??
                                           "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");
        
    public static async Task Main(string[] args)
    {
        if (args.Contains("UrlScan"))
            await UrlScan();
        if (args.Contains("FileScan"))
            await FileScan();
    }

    private static async Task FileScan()
    {
        var vaas = await CreateVaasAndConnect();
        var file = Environment.GetEnvironmentVariable("SCAN_PATH") ?? string.Empty;
        var verdict = await vaas.ForFileAsync(file);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }

    private static async Task<Vaas.Vaas> CreateVaasAndConnect()
    {
        var vaas = new Vaas.Vaas()
        {
            Url = VaasUrl,
        };
        // If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
        var authenticator = new ResourceOwnerPasswordGrantAuthenticator("vaas-customer", UserName, Password, TokenUrl);
        // You may use self registration and create a new username and password for the
        // ResourceOwnerPasswordAuthenticator by yourself like the example above on https://vaas.gdata.de/login

        // Else if you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
        // var authenticator = new ClientCredentialsGrantAuthenticator(
        //     ClientId,
        //     ClientSecret,
        //     TokenUrl
        // );
        await vaas.Connect(await authenticator.GetToken());
        return vaas;
    }

    private static async Task UrlScan()
    {
        var vaas = await CreateVaasAndConnect();

        var uri = new Uri("https://secure.eicar.org/eicar.com.txt");
        var verdict = await vaas.ForUrlAsync(uri);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }
}