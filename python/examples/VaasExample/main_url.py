import asyncio
import os
from vaas import Vaas, ClientCredentialsGrantAuthenticator


async def main():
    authenticator = ClientCredentialsGrantAuthenticator(
        os.getenv("CLIENT_ID"),
        os.getenv("CLIENT_SECRET"),
        "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
    )
    async with Vaas(url="wss://gateway.production.vaas.gdatasecurity.de") as vaas:
        await vaas.connect(await authenticator.get_token())
        url = "https://secure.eicar.org/eicar.com"
        verdict = await vaas.for_url(url)
        print(f"Url {url} is detected as {verdict['Verdict']}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
