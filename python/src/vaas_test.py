import base64
import os
import unittest
from dotenv import load_dotenv

from vaas import Vaas


load_dotenv()

TOKEN = os.getenv("VAAS_TOKEN")
EICAR_BASE64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="


class VaasTest(unittest.IsolatedAsyncioTestCase):
    async def test_raises_error_if_token_is_invalid(self):
        async with Vaas() as vaas:
            token = "ThisIsAnInvalidToken"
            with self.assertRaises(Exception):
                await vaas.connect(token)

    async def test_connects(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)

    async def test_for_sha256_returns_clean_for_clean_sha256(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            verdict = await vaas.for_sha256(
                "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23"
            )
            self.assertEqual(verdict, "Clean")

    async def test_for_sha256_returns_malicious_for_eicar(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            verdict = await vaas.for_sha256(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            )
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_malicious_for_eicar(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            buffer = base64.b64decode(EICAR_BASE64)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_unknown_for_random_buffer(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            buffer = os.urandom(1024)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Clean")

    async def test_for_file_returns_verdict(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            with open("eicar.txt", "wb") as f:
                f.write(base64.b64decode(EICAR_BASE64))
            verdict = await vaas.for_file("eicar.txt")
            self.assertEqual(verdict, "Malicious")


if __name__ == "__main__":
    unittest.main()
