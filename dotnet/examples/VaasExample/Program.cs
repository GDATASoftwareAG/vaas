
using Vaas;

var vaas = new Vaas.Vaas();
var authenticator = new ClientCredentialsGrantAuthenticator(
    Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty,
    Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty,
    new Uri("https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token")
);
await vaas.Connect(await authenticator.GetToken());

var file = Environment.GetEnvironmentVariable("SCAN_PATH") ?? string.Empty;
var verdict = await vaas.ForFileAsync(file);

Console.WriteLine($"{verdict.Sha256} is detected as {verdict.Verdict}");
