using Vaas;

if (args.Length == 0)
{
    Console.WriteLine("Usage TestFiles [FILE]");
    Environment.Exit(1);
}

var vaas = await AuthenticateWithCredentials();

foreach (var path in args)
{
    Console.WriteLine($"Testing {path}");
    var verdict = await vaas.ForFileAsync(path);
    Console.WriteLine($"Tested {path}: Verdict {verdict}");
}

static async Task<Vaas.Vaas> AuthenticateWithCredentials()
{
    DotNetEnv.Env.NoClobber().TraversePath().Load();
    var url = DotNetEnv.Env.GetString(
        "VAAS_URL",
        "wss://gateway-vaas.gdatasecurity.de");
    var tokenEndpoint = new Uri(DotNetEnv.Env.GetString(
        "TOKEN_URL",
        "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"));
    var clientId = DotNetEnv.Env.GetString("CLIENT_ID");
    var clientSecret = DotNetEnv.Env.GetString("CLIENT_SECRET");
    var vaas = new Vaas.Vaas(new VaasOptions() { UseCache = false });
    await vaas.ConnectWithCredentials(clientId, clientSecret, tokenEndpoint, url);
    Console.WriteLine($"Connected to Vaas {url}", url);
    return vaas;
}