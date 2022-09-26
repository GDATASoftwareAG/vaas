import { promises as fs } from "fs";
import { CreateVaasWithClientCredentialsGrant } from "gdata-vaas";

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

  const vaas = await CreateVaasWithClientCredentialsGrant(
    CLIENT_ID,
    CLIENT_SECRET,
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
  );
  const f = await fs.open(SCAN_PATH, "r");
  try {
    const verdict = await vaas.forFile(await f.readFile());
    console.log(verdict);
  } finally {
    f.close();
    vaas.close();
  }
}

main().catch((e) => {
  console.log(e);
});
