import getTokenWithResourceOwnerPasswordGrant from "./getTokenWithResourceOwnerPasswordGrant";

export default class ResourceOwnerPasswordGrantAuthenticator {
  constructor(
    private clientId: string,
    private username: string,
    private password: string,
    private tokenEndpoint: string
  ) {}

  getToken() {
    return getTokenWithResourceOwnerPasswordGrant(
      this.clientId,
      this.username,
      this.password,
      this.tokenEndpoint
    );
  }
}
