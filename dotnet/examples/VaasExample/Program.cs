var vaas = new Vaas.Vaas();
await vaas.ConnectWithCredentials("clientId", "clientSecret", new Uri("https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"));

const string file = "/path/to/file";
var verdict = await vaas.ForFileAsync(file);

Console.WriteLine($"File {file} is {verdict}", file, verdict);