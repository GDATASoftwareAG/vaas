"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
from authlib.integrations.base_client import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client

from .vaas_errors import VaasAuthenticationError


class ClientCredentialsGrantAuthenticator:
    """Tracing interface for Vaas"""

    def __init__(self, client_id, client_secret, token_endpoint, verify=True):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.verify = verify

    async def get_token(self):
        async with AsyncOAuth2Client(
            self.client_id, self.client_secret, verify=self.verify
        ) as client:
            try:
                token = (await client.fetch_token(self.token_endpoint))["access_token"]
                return token
            except Exception as e:
                raise VaasAuthenticationError(e)
