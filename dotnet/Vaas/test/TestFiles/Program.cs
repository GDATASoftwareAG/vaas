using Vaas;
using Vaas.Authentication;
using Vaas.Options;

if (args.Length == 0)
{
    Console.WriteLine("Usage TestFiles [FILE]...");
    Environment.Exit(1);
}

var vaas = AuthenticateWithCredentials();

foreach (var path in args)
{
    Console.WriteLine($"Testing {path}");
    var verdict = await vaas.ForFileAsync(path, CancellationToken.None);
    Console.WriteLine($"Tested {path}: Verdict {verdict}");
}

return;

static IVaas AuthenticateWithCredentials()
{
    DotNetEnv.Env.NoClobber().TraversePath().Load();
    var url = DotNetEnv.Env.GetString(
        "VAAS_URL",
        "https://gateway.production.vaas.gdatasecurity.de"
    );
    var tokenEndpoint = new Uri(
        DotNetEnv.Env.GetString(
            "TOKEN_URL",
            "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
        )
    );
    var clientId = DotNetEnv.Env.GetString("CLIENT_ID");
    var clientSecret = DotNetEnv.Env.GetString("CLIENT_SECRET");

    var authenticator = new ClientCredentialsGrantAuthenticator(
        clientId,
        clientSecret,
        tokenEndpoint
    );

    var vaas = VaasFactory.Create(authenticator, new VaasOptions { VaasUrl = new Uri(url) });

    return vaas;
}
