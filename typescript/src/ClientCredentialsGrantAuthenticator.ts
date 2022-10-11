import getTokenWithClientCredentialsGrant from "./getTokenWithClientCredentialsGrant";

export default class ClientCredentialsGrantAuthenticator {
  constructor(
    private clientId: string,
    private clientSecret: string,
    private tokenEndpoint: string
  ) {}

  getToken() {
    return getTokenWithClientCredentialsGrant(
      this.clientId,
      this.clientSecret,
      this.tokenEndpoint
    );
  }
}
