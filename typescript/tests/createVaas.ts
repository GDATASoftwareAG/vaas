import dotenv from "dotenv";
import { Vaas, CreateVaasWithClientCredentialsGrant } from "../src/Index";

function throwError(errorMessage: string): never {
  throw new Error(errorMessage);
}

function getFromEnvironment(key: string) {
  return (
    process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
  );
}

export default function createVaas(): Promise<Vaas> {
  dotenv.config();
  const CLIENT_ID = getFromEnvironment("CLIENT_ID");
  const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
  const VAAS_URL = getFromEnvironment("VAAS_URL");
  const TOKEN_URL = getFromEnvironment("TOKEN_URL");

  return CreateVaasWithClientCredentialsGrant(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
    VAAS_URL
  );
}
