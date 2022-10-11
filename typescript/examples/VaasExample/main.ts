import { promises as fs } from "fs";
import {
  ClientCredentialsGrantAuthenticator,
  Vaas,
  VaasConnectionClosedError,
  VaasTimeoutError,
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

  const authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
  );

  const vaas = new Vaas();

  const f = await fs.open(SCAN_PATH, "r");

  try {
    while (true) {
      try {
        const verdict = await vaas.forFile(await f.readFile());
        console.log(verdict);
        break;
      } catch (e) {
        if (e instanceof VaasConnectionClosedError) {
          await vaas.connect(await authenticator.getToken());
          continue;
        }
        if (e instanceof VaasTimeoutError) {
          continue;
        }
        throw e;
      }
    }
  } finally {
    f.close();
    vaas.close();
  }
}

main().catch((e) => {
  console.log(e);
});
