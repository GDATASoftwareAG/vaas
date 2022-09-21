import URLSearchParams from "@ungap/url-search-params";
import * as axios from "axios";
import Vaas, { VAAS_URL } from "./Vaas";

async function getTokenWithClientCredentialsGrant(
  clientId: string,
  clientSecret: string,
  tokenEndpoint: string
) {
  var formData = new URLSearchParams();
  formData.append("client_id", clientId);
  formData.append("client_secret", clientSecret);
  formData.append("grant_type", "client_credentials");

  const instance = axios.default.create();
  const response = await instance.post(tokenEndpoint, formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return response.data.access_token;
}

export default async function CreateVaasWithClientCredentialsGrant(
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
