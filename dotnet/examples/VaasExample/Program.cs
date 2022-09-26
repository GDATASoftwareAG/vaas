
var vaas = new Vaas.Vaas();
await vaas.ConnectWithCredentials(
    Environment.GetEnvironmentVariable("CLIENT_ID") ?? string.Empty,
    Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? string.Empty,
    new Uri("https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"));

var file = Environment.GetEnvironmentVariable("SCAN_PATH") ?? string.Empty;
var verdict = await vaas.ForFileAsync(file);

Console.WriteLine($"File {file} is {verdict}", file, verdict);
