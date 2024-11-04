# pylint: disable=C0114,C0116,C0115
import base64
import hashlib
import os
import unittest
from unittest.mock import MagicMock, ANY
import uuid

import websockets.client
from dotenv import load_dotenv

from src.vaas import Vaas, VaasTracing, VaasOptions, ClientCredentialsGrantAuthenticator
from src.vaas import get_ssl_context
from src.vaas.vaas import hash_file
from src.vaas.vaas_errors import VaasConnectionClosedError, VaasInvalidStateError, VaasClientError
import httpx

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TOKEN_URL = os.getenv("TOKEN_URL")
VAAS_URL = os.getenv("VAAS_URL")
SSL_VERIFICATION = os.getenv("SSL_VERIFICATION", "True").lower() in ["true", "1"]

EICAR_BASE64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="


async def create_and_connect(tracing=VaasTracing(), options=VaasOptions()):
    authenticator = ClientCredentialsGrantAuthenticator(
        CLIENT_ID, CLIENT_SECRET, TOKEN_URL, SSL_VERIFICATION
    )
    vaas = Vaas(tracing=tracing, options=options, url=VAAS_URL)

    token = await authenticator.get_token()
    await vaas.connect(token, verify=SSL_VERIFICATION)
    return vaas


def get_disabled_options():
    options = VaasOptions()
    options.use_cache = False
    options.use_hash_lookup = False
    return options


class VaasTest(unittest.IsolatedAsyncioTestCase):
    async def test_raises_error_if_token_is_invalid(self):
        async with Vaas() as vaas:
            token = "ThisIsAnInvalidToken"
            with self.assertRaises(Exception):
                await vaas.connect(token)

    async def test_connects(self):
        async with await create_and_connect():
            pass

    async def test_for_sha256_returns_clean_for_clean_sha256(self):
        async with await create_and_connect() as vaas:
            verdict = await vaas.for_sha256(
                "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e"
            )
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(
                verdict["Sha256"].casefold(),
                "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e".casefold(),
            )

    async def test_use_for_sha256_when_connection_already_closed(self):
        authenticator = ClientCredentialsGrantAuthenticator(
            CLIENT_ID, CLIENT_SECRET, TOKEN_URL, SSL_VERIFICATION
        )
        vaas = Vaas(tracing=VaasTracing(), options=VaasOptions(), url=VAAS_URL)
        ssl_context = get_ssl_context(VAAS_URL, SSL_VERIFICATION)
        websocket = await websockets.client.connect(VAAS_URL, ssl=ssl_context)
        await vaas.connect(
            await authenticator.get_token(),
            websocket=websocket,
            verify=SSL_VERIFICATION,
        )
        await websocket.close()
        with self.assertRaises(VaasConnectionClosedError):
            await vaas.for_sha256(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            )

    async def test_use_for_sha256_if_not_connected(self):
        vaas = Vaas(tracing=VaasTracing(), options=VaasOptions(), url=VAAS_URL)
        with self.assertRaises(VaasInvalidStateError):
            await vaas.for_sha256(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            )

    async def test_for_stream_eicar_form_url_returns_malicious(self):
        async with await create_and_connect() as vaas:
            guid = str(uuid.uuid4())
            async with httpx.AsyncClient() as client:
                response = await client.get("https://secure.eicar.org/eicar.com")
                content_length = response.headers["Content-Length"]
                verdict = await vaas.for_stream(
                    response.aiter_bytes(),
                    content_length,
                    guid=guid
                )
                self.assertEqual(verdict["Verdict"], "Malicious")
                self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_sha256_returns_malicious_for_eicar(self):
        async with await create_and_connect() as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_sha256(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                guid=guid
            )
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(
                verdict["Sha256"].casefold(),
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".casefold(),
            self.assertEqual(verdict["Guid"].casefold(), guid)
            )

    async def test_for_sha256_returns_pup_for_amtso(self):
        async with await create_and_connect() as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_sha256(
                "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad",
                guid=guid
            )
            self.assertEqual(verdict["Verdict"], "Pup")
            self.assertEqual(
                verdict["Sha256"].casefold(),
                "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad".casefold(),
            )
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_buffer_returns_malicious_for_eicar(self):
        async with await create_and_connect() as vaas:
            buffer = base64.b64decode(EICAR_BASE64)
            sha256 = hashlib.sha256(buffer).hexdigest()
            guid = str(uuid.uuid4())
            verdict = await vaas.for_buffer(buffer, guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_stream_returns_malicious_for_eicar(self):
        async with await create_and_connect() as vaas:
            buffer = base64.b64decode(EICAR_BASE64)
            guid = str(uuid.uuid4())
            verdict = await vaas.for_buffer(buffer, guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_buffer_returns_unknown_for_random_buffer(self):
        async with await create_and_connect() as vaas:
            buffer = os.urandom(1024)
            sha256 = hashlib.sha256(buffer).hexdigest()
            guid = str(uuid.uuid4())
            verdict = await vaas.for_buffer(buffer, guid=guid)
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_file_returns_verdict(self):
        async with await create_and_connect() as vaas:
            with open("eicar.txt", "wb") as f:
                f.write(base64.b64decode(EICAR_BASE64))
            sha256 = hash_file("eicar.txt")
            guid = str(uuid.uuid4())
            verdict = await vaas.for_file("eicar.txt", guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_file_returns_verdict_if_no_cache_or_shed(self):
        options = get_disabled_options()

        async with await create_and_connect(options=options) as vaas:
            with open("eicar.txt", "wb") as f:
                f.write(base64.b64decode(EICAR_BASE64))
            sha256 = hash_file("eicar.txt")
            guid = str(uuid.uuid4())
            verdict = await vaas.for_file("eicar.txt", guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_url_returns_malicious_for_eicar(self):
        options = get_disabled_options()
        async with await create_and_connect(options=options) as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_url("https://secure.eicar.org/eicarcom2.zip", guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_url_without_shed_and_cache_returns_clean_for_robots_txt(self):
        options = get_disabled_options()
        async with await create_and_connect(options=options) as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_url("https://www.gdata.de/robots.txt", guid=guid)
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_url_without_cache_returns_clean_for_robots_txt(self):
        options = VaasOptions()
        options.use_cache = False
        options.use_hash_lookup = True
        async with await create_and_connect(options=options) as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_url("https://www.gdata.de/robots.txt", guid=guid)
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_url__with_url_with_status_code_4xx__raises_VaasClientError(self):
        options = get_disabled_options()
        async with await create_and_connect(options=options) as vaas:
            with self.assertRaises(VaasClientError, msg="Call failed with status code 404 (Not Found): GET https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere") as error:
                await vaas.for_url("https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere")
            self.assertEqual(str(error.msg), "Call failed with status code 404 (Not Found): GET https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere")

    async def test_for_buffer_traces(self):
        tracing = VaasTracing()
        tracing.trace_hash_request = MagicMock()
        tracing.trace_upload_request = MagicMock()
        async with await create_and_connect(tracing=tracing) as vaas:
            buffer = os.urandom(1024)
            sha256 = hashlib.sha256(buffer).hexdigest()
            guid = str(uuid.uuid4())
            verdict = await vaas.for_buffer(buffer, guid=guid)
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)
            tracing.trace_hash_request.assert_called_with(ANY)
            tracing.trace_upload_request.assert_called_with(ANY, 1024)

    async def test_for_empty_buffer_returns_clean(self):
        async with await create_and_connect() as vaas:
            buffer = bytes("", "utf-8")
            sha256 = hashlib.sha256(buffer).hexdigest()
            guid = str(uuid.uuid4())
            verdict = await vaas.for_buffer(buffer, guid=guid)
            self.assertEqual(verdict["Verdict"], "Clean")
            self.assertEqual(verdict["Sha256"].casefold(), sha256.casefold())
            self.assertEqual(verdict["Guid"].casefold(), guid)

    async def test_for_url_returns_detections_and_mime_type(self):
        options = get_disabled_options()
        async with await create_and_connect(options=options) as vaas:
            guid = str(uuid.uuid4())
            verdict = await vaas.for_url("https://secure.eicar.org/eicar.com.txt", guid=guid)
            self.assertEqual(verdict["Verdict"], "Malicious")
            self.assertIsNotNone(verdict["Detection"])
            self.assertEqual(verdict['FileType'], "EICAR virus test files")
            self.assertEqual(verdict['MimeType'], "text/plain")


if __name__ == "__main__":
    unittest.main()
