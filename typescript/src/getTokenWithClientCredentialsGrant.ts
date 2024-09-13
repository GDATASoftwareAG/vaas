import URLSearchParams from "@ungap/url-search-params";
import axios from "axios";
import http from 'http';
import https from 'https';

export default async function getTokenWithClientCredentialsGrant(
  clientId: string,
  clientSecret: string,
  tokenEndpoint: string,
) {
  var formData = new URLSearchParams();
  formData.append("client_id", clientId);
  formData.append("client_secret", clientSecret);
  formData.append("grant_type", "client_credentials");

  const instance = axios.create({
    httpAgent: new http.Agent({ keepAlive: false }),
    httpsAgent: new https.Agent({ keepAlive: false }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  const response = await instance.post(tokenEndpoint, formData);

  return response.data.access_token;
}
