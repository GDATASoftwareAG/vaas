import URLSearchParams from "@ungap/url-search-params";
import * as axios from "axios";

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

  const instance = axios.default.create();
  const response = await instance.post(tokenEndpoint, formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return response.data.access_token;
}
