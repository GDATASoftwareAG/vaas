import asyncio
from vaas.vaas import Vaas


async def main():
    async with Vaas() as vaas:
        await vaas.connect_with_client_credentials(
            "clientId",
            "clientSecret",
            "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token",
            )
        path = "/path/to/file"
        verdict = await vaas.for_file(path)
        print(f"File {path} is detected as {verdict}")


if __name__ ==  '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())    