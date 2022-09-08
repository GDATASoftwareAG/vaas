"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
import os
import hashlib
import json
import time
import uuid
from typing import Optional
import asyncio
from asyncio import Future
import ssl
from urllib.parse import urlparse
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


class VaasOptions:
    """Configure behaviour of VaaS"""

    def __init__(self):
        self.use_cache = True
        self.use_shed = True


def hash_file(filename):
    """Return sha256 hash for file"""
    block_size = 65536

    h_sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        buffer = file.read(block_size)
        while len(buffer) > 0:
            h_sha256.update(buffer)
            buffer = file.read(block_size)

    return h_sha256.hexdigest()


def is_ssl_url(url):
    """check if url is wss"""
    parsed_url = urlparse(url)
    return parsed_url.scheme == "wss"


def get_ssl_context(url, verify):
    """return ssl context for websockets"""
    if not is_ssl_url(url):
        return None
    if verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # pylint: disable=W0212


def connect_websocket(url, verify):
    """returns a websocket instance"""
    ssl_context = get_ssl_context(url, verify)
    return websockets.client.connect(url, ssl=ssl_context)


class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(self, tracing=VaasTracing(), options=VaasOptions()):
        self.tracing = tracing
        self.loop_result = None
        self.websocket = None
        self.session_id = None
        self.results = {}
        self.httpx_client: Optional[httpx.AsyncClient] = None
        self.options = options

    async def connect(self, token, url=URL, verify=True):
        """Connect to VaaS

        token -- OpenID Connect token signed by a trusted identity provider
        """
        self.websocket = await connect_websocket(url, verify)
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
            "use_shed": self.options.use_shed,
            "use_cache": self.options.use_cache,
        }
        response_message = self.__response_message_for_guid(guid)
        await self.websocket.send(json.dumps(verdict_request))

        try:
            result = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError as ex:
            self.tracing.trace_hash_request_timeout()
            raise VaasTimeoutError() from ex

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

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(
            None, lambda: hashlib.sha256(buffer).hexdigest()
        )

        response = await self.__for_sha256(sha256)
        verdict = response.get("verdict")

        if verdict == "Unknown":
            verdict = await self._for_unknown_buffer(response, buffer, len(buffer))

        return verdict

    async def _for_unknown_buffer(self, response, buffer, buffer_len):
        start = time.time()
        guid = response.get("guid")
        token = response.get("upload_token")
        url = response.get("url")
        response_message = self.__response_message_for_guid(guid)
        await self.__upload(token, url, buffer, buffer_len)
        try:
            verdict = (await asyncio.wait_for(response_message, timeout=TIMEOUT)).get(
                "verdict"
            )
        except asyncio.TimeoutError as ex:
            self.tracing.trace_upload_result_timeout(buffer_len)
            raise VaasTimeoutError() from ex
        self.tracing.trace_upload_request(time.time() - start, buffer_len)
        return verdict

    async def for_file(self, path):
        """Returns the verdict for a file"""

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(None, lambda: hash_file(path))

        response = await self.__for_sha256(sha256)
        verdict = response.get("verdict")

        if verdict == "Unknown":
            content_length = os.path.getsize(path)
            async with aiofiles.open(path, mode="rb") as file:
                verdict = await self._for_unknown_buffer(response, file, content_length)

        return verdict

    async def __upload(self, token, upload_uri, buffer_or_file, content_length):
        jwt = JWT()
        decoded_token = jwt.decode(token, do_verify=False)
        trace_id = decoded_token.get("traceId")
        try:
            await self.httpx_client.put(
                url=upload_uri,
                content=buffer_or_file,
                headers={
                    "Authorization": token,
                    "traceParent": trace_id,
                    "Content-Length": str(content_length),
                },
                timeout=UPLOAD_TIMEOUT,
            )
        except httpx.TimeoutException as ex:
            self.tracing.trace_upload_timeout(content_length)
            raise VaasTimeoutError() from ex

    async def for_url(self, url):
        """Returns the verdict for a file from an url"""
        response = await self.httpx_client.get(url)
        buffer = response.content
        return await self.for_buffer(buffer)
