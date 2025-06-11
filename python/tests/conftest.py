import pytest
from src.vaas import Vaas, VaasTracing, ClientCredentialsGrantAuthenticator
import os
from dotenv import load_dotenv

load_dotenv()

@pytest.fixture
async def vaas():
    authenticator = ClientCredentialsGrantAuthenticator(
        os.getenv("CLIENT_ID"),
        os.getenv("CLIENT_SECRET"),
        os.getenv("TOKEN_URL"),
        os.getenv("SSL_VERIFICATION", "true").lower() in ["true", "1"]
    )

    client = Vaas(
        tracing=VaasTracing(),
        authenticator=authenticator,
        url=os.getenv("VAAS_URL")
    )
    try:
        yield client
    finally:
        await client.httpx_client.aclose()
