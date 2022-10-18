import unittest
import os
from dotenv import load_dotenv
from src.vaas import ClientCredentialsGrantAuthenticator, VaasAuthenticationError

load_dotenv()
TOKEN_URL = os.getenv("TOKEN_URL")


class ClientCredentialsGrantAuthenticatorTest(unittest.IsolatedAsyncioTestCase):
    async def test_raises_error_if_credentials_are_invalid(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", TOKEN_URL
        )

        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_invalid(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", "isbad"
        )

        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_wrong(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id", "invalid_secret", "https://gdata.de"
        )

        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()

    async def test_raises_error_if_token_url_is_doesnotexist(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            "invalid_id",
            "invalid_secret",
            "https://thishostnamedoesneverexistanywhere.de",
        )

        with self.assertRaises(VaasAuthenticationError):
            await authenticator.get_token()
