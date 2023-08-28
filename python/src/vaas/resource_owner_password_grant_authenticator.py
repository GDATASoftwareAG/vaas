"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
from .vaas_errors import VaasAuthenticationError
from authlib.integrations.httpx_client import AsyncOAuth2Client

class ResourceOwnerPasswordGrantAuthenticator:
    """Tracing interface for Vaas"""

    def __init__(self, client_id, user_name, password, token_endpoint, verify=True):
        self.client_id = client_id
        self.user_name = user_name
        self.password = password
        self.token_endpoint = token_endpoint
        self.verify = verify

    async def get_token(self):
        async with AsyncOAuth2Client(
                self.client_id, verify=self.verify
        ) as client:
            try:
                token = \
                (await client.fetch_token(self.token_endpoint, username=self.user_name, password=self.password, grant_type="password"))[
                    "access_token"]
                return token
            except Exception as e:
                raise VaasAuthenticationError(e)
