import dotenv from "dotenv";
import {ClientCredentialsGrantAuthenticator, Vaas} from "../src/Index";

function throwError(errorMessage: string): never {
  throw new Error(errorMessage);
}

function getFromEnvironment(key: string) {
  return (
    process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
  );
}

export default async function createVaas(): Promise<Vaas> {
  dotenv.config();
  const CLIENT_ID = getFromEnvironment("CLIENT_ID");
  const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
  const VAAS_URL = getFromEnvironment("VAAS_URL");
  const TOKEN_URL = getFromEnvironment("TOKEN_URL");

  const authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
  );

  let vaas = new Vaas();
  let token = await authenticator.getToken()
  await vaas.connect(token, VAAS_URL);
  return vaas;
}
