import time
from authlib.integrations.httpx_client import AsyncOAuth2Client

from .authenticator_interface import AuthenticatorInterface
from ..vaas_errors import VaasAuthenticationError


class ClientCredentialsGrantAuthenticator(AuthenticatorInterface):
    def __init__(self, client_id, client_secret, token_endpoint, verify=True):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.verify = verify

        self._access_token = None
        self._expires_at = 0  # UNIX timestamp

    async def get_token(self):
        if self._access_token and time.time() < self._expires_at:
            return self._access_token

        async with AsyncOAuth2Client(
            self.client_id, self.client_secret, verify=self.verify
        ) as client:
            try:
                token_response = await client.fetch_token(self.token_endpoint)
                self._access_token = token_response["access_token"]
                expires_in = token_response.get("expires_in", 3600)
                self._expires_at = time.time() + expires_in
                return self._access_token
            except Exception as e:
                raise VaasAuthenticationError(e)