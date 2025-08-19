import os
import pytest

from dotenv import load_dotenv
from src.vaas import ClientCredentialsGrantAuthenticator, VaasAuthenticationError

load_dotenv()
TOKEN_URL = os.getenv("TOKEN_URL")


class TestClientCredentialsGrantAuthenticator:

    @pytest.mark.asyncio()
    async def test_raises_error_if_credentials_are_invalid(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", TOKEN_URL
        )

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_invalid(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", "isbad"
        )

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_wrong(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", "https://gdata.de"
        )

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_doesnotexist(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id",
            "invalid_secret",
            "https://thishostnamedoesneverexistanywhere.de",
        )

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_get_token_request_twice_get_cached_token(self):
        token_url = os.getenv("TOKEN_URL")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")

        if token_url is None:
            token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"

        authenticator = ClientCredentialsGrantAuthenticator(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=token_url
        )

        token = await authenticator.get_token()
        cached_token = await authenticator.get_token()
        assert token == cached_token