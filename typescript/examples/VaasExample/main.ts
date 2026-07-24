import { promises as fs } from "fs";
import {
  ClientCredentialsGrantAuthenticator,
  Vaas,
  VaasOptions,
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
  const SCAN_PATH = getFromEnvironment("SCAN_PATH");
  const TOKEN_URL = getFromEnvironment("TOKEN_URL");
  const VAAS_URL = getFromEnvironment("VAAS_URL");

  const authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
  );

  const options = new VaasOptions();
  options.vaasUrl = VAAS_URL;
  const vaas = new Vaas(authenticator, options);

  const f = await fs.open(SCAN_PATH, "r");

  const verdict = await vaas.forFile(await f.readFile());
  console.log(verdict);
  f.close();
}

main().catch((e) => {
  console.log(e);
});
