using Vaas;
using Vaas.Authentication;

if (args.Length == 0)
{
    Console.WriteLine("Usage TestFiles [FILE]...");
    Environment.Exit(1);
}

var vaas = await AuthenticateWithCredentials();

foreach (var path in args)
{
    Console.WriteLine($"Testing {path}");
    var verdict = await vaas.ForFileAsync(path, CancellationToken.None);
    Console.WriteLine($"Tested {path}: Verdict {verdict}");
}

static async Task<IVaas> AuthenticateWithCredentials()
{
    DotNetEnv.Env.NoClobber().TraversePath().Load();
    var url = DotNetEnv.Env.GetString("VAAS_URL", "wss://gateway.production.vaas.gdatasecurity.de");
    var tokenEndpoint = new Uri(
        DotNetEnv.Env.GetString(
            "TOKEN_URL",
            "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
        )
    );
    var clientId = DotNetEnv.Env.GetString("CLIENT_ID");
    var clientSecret = DotNetEnv.Env.GetString("CLIENT_SECRET");

    var vaas = VaasFactory.Create(
        new VaasOptions()
        {
            Url = new Uri(url),
            TokenUrl = tokenEndpoint,
            Credentials = new TokenRequest
            {
                GrantType = GrantType.ClientCredentials,
                ClientId = clientId,
                ClientSecret = clientSecret,
            },
        }
    );

    return vaas;
}
