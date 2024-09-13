import URLSearchParams from "@ungap/url-search-params";
import axios from "axios";
import http from 'http';
import https from 'https';

export default async function getTokenWithResourceOwnerPasswordGrant(
  clientId: string,
  username: string,
  password: string,
  tokenEndpoint: string,
) {
  var formData = new URLSearchParams();
  formData.append("client_id", clientId);
  formData.append("username", username);
  formData.append("password", password);
  formData.append("grant_type", "password");

  const instance = axios.create({
    httpAgent: new http.Agent({ keepAlive: false }),
    httpsAgent: new https.Agent({ keepAlive: false }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  const response = await instance.post(tokenEndpoint, formData);
  return response.data.access_token;
}
