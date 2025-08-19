import os
import pytest

from dotenv import load_dotenv
from src.vaas import ResourceOwnerPasswordGrantAuthenticator, VaasAuthenticationError, Vaas

load_dotenv()
TOKEN_URL = os.getenv("TOKEN_URL")


class TestResourceOwnerPasswordGrantAuthenticator():

    @pytest.mark.asyncio()
    async def test_raises_error_if_credentials_are_invalid(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint=TOKEN_URL)

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_invalid(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="https://")

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_wrong(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="gateway.production.vaas.gdatasecurity.de")

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_raises_error_if_token_url_is_doesnotexist(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="gateway.production.vaas.gdatasecurity.de/nocontenthere")

        with pytest.raises(VaasAuthenticationError):
            await authenticator.get_token()

    @pytest.mark.asyncio()
    async def test_for_url_with_resource_owner_password_grant_returns_malicious(self):
        token_url = os.getenv("TOKEN_URL")
        vaas_url = os.getenv("VAAS_URL")
        client_id = os.getenv("VAAS_CLIENT_ID")
        username = os.getenv("VAAS_USER_NAME")
        password = os.getenv("VAAS_PASSWORD")

        if token_url is None:
            token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
        if vaas_url is None:
            vaas_url = "https://gateway.production.vaas.gdatasecurity.de"

        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            client_id=client_id,
            user_name=username,
            password=password,
            token_endpoint=token_url
        )

        vaas = Vaas(url=vaas_url, authenticator=authenticator)
        url = "https://secure.eicar.org/eicar.com"
        verdict = await vaas.for_url(url)
        print(f"Url {url} is detected as {verdict.verdict}")
        assert verdict.verdict, "Malicious"

    @pytest.mark.asyncio()
    async def test_get_token_request_twice_get_cached_token(self):
        token_url = os.getenv("TOKEN_URL")
        client_id = os.getenv("VAAS_CLIENT_ID")
        username = os.getenv("VAAS_USER_NAME")
        password = os.getenv("VAAS_PASSWORD")

        if token_url is None:
            token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"

        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            client_id=client_id,
            user_name=username,
            password=password,
            token_endpoint=token_url
        )

        token = await authenticator.get_token()
        cached_token = await authenticator.get_token()
        assert token == cached_token
