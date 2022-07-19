"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
import hashlib
import json
import time
import uuid
import asyncio
from asyncio import Future
import aiofiles
from jwt import JWT
import httpx
import websockets.client
from authlib.integrations.httpx_client import AsyncOAuth2Client


URL = "wss://gateway-vaas.gdatasecurity.de"
TIMEOUT = 60
HTTP2 = False
# TODO: Set to default of 5 once Vaas upload endpoint is 100% streaming
UPLOAD_TIMEOUT = 600
USE_CACHE = True
USE_SHED = True


class VaasTracing:
    """Tracing interface for Vaas"""

    def trace_hash_request(self, elapsed_in_seconds):
        """Trace hash request in seconds"""

    def trace_upload_request(self, elapsed_in_seconds, file_size):
        """Trace upload request in seconds"""

    def trace_hash_request_timeout(self):
        """Trace timeout while waiting for hash verdict"""

    def trace_upload_result_timeout(self, file_size):
        """Trace timeout while waiting for verdict for uploaded file"""

    def trace_upload_timeout(self, file_size):
        """Trace upload timeout"""


class VaasTimeoutError(BaseException):
    """Generic timeout"""


class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(self, tracing=VaasTracing()):
        self.tracing = tracing
        self.loop_result = None
        self.websocket = None
        self.session_id = None
        self.results = {}
        self.httpx_client = httpx.AsyncClient(http2=HTTP2)

    async def connect(self, token, url=URL, verify=True):
        """Connect to VaaS

        token -- OpenID Connect token signed by a trusted identity provider
        """
        self.websocket = await websockets.client.connect(url)
        authenticate_request = {"kind": "AuthRequest", "token": token}

        await self.websocket.send(json.dumps(authenticate_request))

        authentication_response = json.loads(await self.websocket.recv())
        if not authentication_response.get("success", False):
            raise Exception("Authentication failed")
        self.session_id = authentication_response["session_id"]

        self.loop_result = asyncio.ensure_future(
            self.__receive_loop()
        )  # fire and forget async_foo()

        self.httpx_client = httpx.AsyncClient(http2=HTTP2, verify=verify)

    async def connect_with_client_credentials(
        self, client_id, client_secret, token_endpoint, url=URL, verify=True
    ):
        """Connect to VaaS with client credentials grant

        :param str client_id: Client ID provided by G DATA
        :param str client_secret: Client secret provided by G DATA
        :param str token_endpoint: Token endpoint of identity provider
        :param str url: Websocket endpoint for verdict requests
        :param bool verify: This switch turns off SSL validation when set to False; default: True

        """
        async with AsyncOAuth2Client(client_id, client_secret, verify=verify) as client:
            token = (await client.fetch_token(token_endpoint))["access_token"]
        await self.connect(token, url, verify)

    async def close(self):
        """Close the connection"""
        if self.websocket is not None:
            await self.websocket.close()
        if self.loop_result is not None:
            await self.loop_result
        if self.httpx_client is not None:
            await self.httpx_client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.close()

    async def for_sha256(self, sha256):
        """Returns the verdict for a SHA256 checksum"""
        result = await self.__for_sha256(sha256)
        verdict = result.get("verdict")
        return verdict

    async def __for_sha256(self, sha256):
        start = time.time()
        guid = str(uuid.uuid4())
        verdict_request = {
            "kind": "VerdictRequest",
            "sha256": sha256,
            "session_id": self.session_id,
            "guid": guid,
            "use_shed": USE_SHED,
            "use_cache": USE_CACHE,
        }
        response_message = self.__response_message_for_guid(guid)
        await self.websocket.send(json.dumps(verdict_request))

        try:
            result = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError:
            self.tracing.trace_hash_request_timeout()
            raise VaasTimeoutError()

        self.tracing.trace_hash_request(time.time() - start)
        return result

    def __response_message_for_guid(self, guid):
        result = Future()
        self.results[guid] = result
        return result

    async def __receive_loop(self):
        async for message in self.websocket:
            vaas_message = json.loads(message)
            if vaas_message.get("kind") == "VerdictResponse":
                guid = vaas_message.get("guid")
                future = self.results.get(guid)
                if future is not None:
                    future.set_result(vaas_message)

    async def for_buffer(self, buffer):
        """Returns the verdict for a buffer"""
        start = time.time()

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(
            None, lambda: hashlib.sha256(buffer).hexdigest()
        )

        response = await self.__for_sha256(sha256)
        verdict = response.get("verdict")

        if verdict == "Unknown":
            guid = response.get("guid")
            token = response.get("upload_token")
            url = response.get("url")
            response_message = self.__response_message_for_guid(guid)
            await self.__upload(token, url, buffer)
            try:
                verdict = (
                    await asyncio.wait_for(response_message, timeout=TIMEOUT)
                ).get("verdict")
            except asyncio.TimeoutError:
                self.tracing.trace_upload_result_timeout(len(buffer))
                raise VaasTimeoutError()
            self.tracing.trace_upload_request(time.time() - start, len(buffer))

        return verdict

    async def for_file(self, path):
        """Returns the verdict for a file"""
        async with aiofiles.open(path, mode="rb") as open_file:
            return await self.for_buffer(await open_file.read())

    async def __upload(self, token, upload_uri, buffer):
        jwt = JWT()
        decoded_token = jwt.decode(token, do_verify=False)
        trace_id = decoded_token.get("traceId")
        try:
            await self.httpx_client.put(
                url=upload_uri,
                data=buffer,
                headers={"Authorization": token, "traceParent": trace_id},
                timeout=UPLOAD_TIMEOUT,
            )
        except httpx.TimeoutException:
            self.tracing.trace_upload_timeout(len(buffer))
            raise VaasTimeoutError()
