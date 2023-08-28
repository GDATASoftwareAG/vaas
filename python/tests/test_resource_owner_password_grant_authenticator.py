import unittest
import os
from dotenv import load_dotenv
from src.vaas import ResourceOwnerPasswordGrantAuthenticator, VaasAuthenticationError, Vaas

load_dotenv()
TOKEN_URL = os.getenv("TOKEN_URL")


class ResourceOwnerPasswordGrantAuthenticatorTest(unittest.IsolatedAsyncioTestCase):

    async def test_raises_error_if_credentials_are_invalid(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint=TOKEN_URL)
        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_invalid(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="https://")
        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_wrong(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="gateway.production.vaas.gdatasecurity.de")
        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_doesnotexist(self):
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "invalid_client_id",
            "invalid_user",
            "invalid_password",
            token_endpoint="gateway.production.vaas.gdatasecurity.de/nocontenthere")
        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_for_url_with_resource_owner_password_grant_returns_malicious(self):
        token_url = os.getenv("TOKEN_URL")
        vaas_url = os.getenv("VAAS_URL")
        client_id = os.getenv("VAAS_CLIENT_ID")
        username = os.getenv("VAAS_USER_NAME")
        password = os.getenv("VAAS_PASSWORD")

        if token_url is None:
            token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
        if vaas_url is None:
            vaas_url = "wss://gateway.production.vaas.gdatasecurity.de"

        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            client_id=client_id,
            user_name=username,
            password=password,
            token_endpoint=token_url
        )
        async with Vaas(url=vaas_url) as vaas:
            await vaas.connect(await authenticator.get_token())
            url = "https://secure.eicar.org/eicar.com"
            verdict = await vaas.for_url(url)
            print(f"Url {url} is detected as {verdict.get('Verdict')}")
        self.assertEqual(verdict.get("Verdict"), "Malicious")
