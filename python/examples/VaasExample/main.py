from argparse import _AttributeHolder
import asyncio
import os
import dotenv
from vaas import Vaas, ClientCredentialsGrantAuthenticator


async def main():
    dotenv.load_dotenv()
    token_url = os.getenv("TOKEN_URL")
    vaas_url = os.getenv("VAAS_URL")

    if token_url is None:
        token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
    if vaas_url is None:
        vaas_url = "https://gateway.production.vaas.gdatasecurity.de"

    authenticator = ClientCredentialsGrantAuthenticator(
        os.getenv("CLIENT_ID"),
        os.getenv("CLIENT_SECRET"),
        token_endpoint=token_url
    )

    vaas = Vaas(url=vaas_url, authenticator=authenticator)
    path = os.getenv("SCAN_PATH")
    verdict = await vaas.for_file(path)
    print(f"{verdict.sha256} is detected as {verdict.verdict}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
