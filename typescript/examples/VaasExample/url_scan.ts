import {
  ClientCredentialsGrantAuthenticator,
  Vaas,
} from "gdata-vaas";

function throwError(errorMessage: string): never {
  throw new Error(errorMessage);
}

function getFromEnvironment(key: string) {
  return (
    process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
  );
}

async function main() {
  const CLIENT_ID = getFromEnvironment("CLIENT_ID");
  const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
  const TOKEN_URL =
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token";

  const authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL
  );

  const vaas = new Vaas();
  const token = await authenticator.getToken()
  await vaas.connect(token);
  
  const url = new URL("https://secure.eicar.org/eicar.com");

  const verdict = await vaas.forUrl(url);
  console.log(verdict);
  vaas.close();
}

main().catch((e) => {
  console.log(e);
});
