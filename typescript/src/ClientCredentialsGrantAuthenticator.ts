import getTokenWithClientCredentialsGrant from "./getTokenWithClientCredentialsGrant";

export class ClientCredentialsGrantAuthenticator {
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
