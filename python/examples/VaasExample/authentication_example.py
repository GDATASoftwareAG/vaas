import asyncio
import os
from vaas import Vaas, ClientCredentialsGrantAuthenticator, ResourceOwnerPasswordGrantAuthenticator

USE_RESOURCE_OWNER_PASSWORD_GRANT_AUTHENTICATOR = False

async def main():
    token_url = os.getenv("TOKEN_URL")
    vaas_url = os.getenv("VAAS_URL")

    if token_url is None:
        token_url = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
    if vaas_url is None:
        vaas_url = "wss://gateway.production.vaas.gdatasecurity.de"

    # If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
    if USE_RESOURCE_OWNER_PASSWORD_GRANT_AUTHENTICATOR:
        authenticator = ResourceOwnerPasswordGrantAuthenticator(
            "vaas-customer",
            os.getenv("VAAS_USER_NAME"),
            os.getenv("VAAS_PASSWORD"),
            token_endpoint=token_url
        )
    # You may use self registration and create a new username and password for the
    # ResourceOwnerPasswordAuthenticator by yourself like the example above on https://vaas.gdata.de/login

    # Else if you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
    else:
        authenticator = ClientCredentialsGrantAuthenticator(
            os.getenv("CLIENT_ID"),
            os.getenv("CLIENT_SECRET"),
            token_endpoint=token_url
        )

    async with Vaas(url=vaas_url) as vaas:
        await vaas.connect(await authenticator.get_token())
        url = "https://secure.eicar.org/eicar.com"
        verdict = await vaas.for_url(url)
        print(f"Url {url} is detected as {verdict['Verdict']}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
