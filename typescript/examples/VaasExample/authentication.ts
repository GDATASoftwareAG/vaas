
import { promises as fs } from "fs";
import {
  ClientCredentialsGrantAuthenticator,
  ResourceOwnerPasswordGrantAuthenticator,
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
  const VAAS_USER_NAME = getFromEnvironment("VAAS_USER_NAME");
  const VAAS_PASSWORD = getFromEnvironment("VAAS_PASSWORD");
  const SCAN_PATH = getFromEnvironment("SCAN_PATH");
  const TOKEN_URL = getFromEnvironment("TOKEN_URL");
  const VAAS_URL = getFromEnvironment("VAAS_URL");

  // If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
  const authenticator = new ResourceOwnerPasswordGrantAuthenticator(
    "vaas-customer",
    VAAS_USER_NAME,
    VAAS_PASSWORD,
    TOKEN_URL
  );

  // You may use self registration and create a new username and password for the
  // ResourceOwnerPasswordAuthenticator by yourself like the example above on https://vaas.gdata.de/login

  // Else if you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
  // const authenticator = new ClientCredentialsGrantAuthenticator(
  //   CLIENT_ID,
  //   CLIENT_SECRET,
  //   TOKEN_URL
  // );

  const vaas = new Vaas();
  const token = await authenticator.getToken()
  await vaas.connect(token, VAAS_URL);

  const f = await fs.open(SCAN_PATH, "r");

  const verdict = await vaas.forFile(await f.readFile());
  console.log(verdict);
  f.close();
  vaas.close();
}

main().catch((e) => {
  console.log(e);
});
