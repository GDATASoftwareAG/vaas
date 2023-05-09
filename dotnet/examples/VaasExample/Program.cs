using Vaas;

namespace VaasExample;


public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Contains("UrlScan"))
            await UrlScan();
        if (args.Contains("FileScan"))
            await FileScan();
    }

    private static async Task FileScan()
    {
        var vaas = new Vaas.Vaas();
        vaas.Url = new Uri("wss://gateway.production.vaas.gdatasecurity.de");
        var authenticator = new ClientCredentialsGrantAuthenticator(
            Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty,
            Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty,
            new Uri("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token")
        );
        await vaas.Connect(await authenticator.GetToken());

        var file = Environment.GetEnvironmentVariable("SCAN_PATH") ?? string.Empty;
        var verdict = await vaas.ForFileAsync(file);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }

    private static async Task UrlScan()
    {
        var vaas = new Vaas.Vaas();
        vaas.Url = new Uri("wss://gateway.production.vaas.gdatasecurity.de");
        var authenticator = new ClientCredentialsGrantAuthenticator(
            Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty,
            Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty,
            new Uri("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token")
        );
        await vaas.Connect(await authenticator.GetToken());

        var uri = new Uri("https://secure.eicar.org/eicar.com.txt");
        var verdict = await vaas.ForUrlAsync(uri);

        Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
    }
}