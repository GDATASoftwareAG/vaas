import getTokenWithClientCredentialsGrant from "./getTokenWithClientCredentialsGrant";
import { Vaas, VAAS_URL } from "./Vaas";

/** @deprecated Use ClientCredentialsGrantAuthenticator */
export async function CreateVaasWithClientCredentialsGrant(
  clientId: string,
  clientSecret: string,
  tokenEndpoint: string,
  vaasUrl = VAAS_URL
): Promise<Vaas> {
  const token = await getTokenWithClientCredentialsGrant(
    clientId,
    clientSecret,
    tokenEndpoint
  );
  const vaas = new Vaas();
  await vaas.connect(token, vaasUrl);
  return vaas;
}
