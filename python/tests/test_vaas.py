# pylint: disable=C0114,C0116,C0115
import base64
import os
import unittest
from unittest.mock import MagicMock, ANY
from dotenv import load_dotenv
from src.vaas import Vaas, VaasTracing, VaasOptions

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TOKEN_URL = os.getenv("TOKEN_URL")
VAAS_URL = os.getenv("VAAS_URL")

EICAR_BASE64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="


async def create_and_connect(tracing=VaasTracing(), options=VaasOptions()):
    vaas = Vaas(tracing=tracing, options=options)
    await vaas.connect_with_client_credentials(
        CLIENT_ID, CLIENT_SECRET, TOKEN_URL, VAAS_URL
    )
    return vaas


class VaasTest(unittest.IsolatedAsyncioTestCase):
    async def test_raises_error_if_token_is_invalid(self):
        async with Vaas() as vaas:
            token = "ThisIsAnInvalidToken"
            with self.assertRaises(Exception):
                await vaas.connect(token)

    async def test_connects(self):
        async with await create_and_connect() as vaas:
            pass

    async def test_for_sha256_returns_clean_for_clean_sha256(self):
        async with await create_and_connect() as vaas:
            verdict = await vaas.for_sha256(
                "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23"
            )
            self.assertEqual(verdict, "Clean")

    async def test_for_sha256_returns_malicious_for_eicar(self):
        async with await create_and_connect() as vaas:
            verdict = await vaas.for_sha256(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            )
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_malicious_for_eicar(self):
        async with await create_and_connect() as vaas:
            buffer = base64.b64decode(EICAR_BASE64)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_unknown_for_random_buffer(self):
        async with await create_and_connect() as vaas:
            buffer = os.urandom(1024)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Clean")

    async def test_for_file_returns_verdict(self):
        async with await create_and_connect() as vaas:
            with open("eicar.txt", "wb") as f:
                f.write(base64.b64decode(EICAR_BASE64))
            verdict = await vaas.for_file("eicar.txt")
            self.assertEqual(verdict, "Malicious")

    async def test_for_file_returns_verdict_if_no_cache_or_shed(self):
        options = VaasOptions()
        options.use_cache = False
        options.use_shed = False

        async with await create_and_connect(options=options) as vaas:
            with open("eicar.txt", "wb") as f:
                f.write(base64.b64decode(EICAR_BASE64))
            verdict = await vaas.for_file("eicar.txt")
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_traces(self):
        tracing = VaasTracing()
        tracing.trace_hash_request = MagicMock()
        tracing.trace_upload_request = MagicMock()
        async with await create_and_connect(tracing=tracing) as vaas:
            buffer = os.urandom(1024)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Clean")
            tracing.trace_hash_request.assert_called_with(ANY)
            tracing.trace_upload_request.assert_called_with(ANY, 1024)


if __name__ == "__main__":
    unittest.main()
