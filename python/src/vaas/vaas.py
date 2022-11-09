"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
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
from .vaas_errors import (
    VaasInvalidStateError,
    VaasConnectionClosedError,
    VaasTimeoutError,
)

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

    def trace_url_request(self, elapsed_in_seconds):
        """Trace url request in seconds"""

    def trace_hash_request_timeout(self):
        """Trace timeout while waiting for hash verdict"""

    def trace_upload_result_timeout(self, file_size):
        """Trace timeout while waiting for verdict for uploaded file"""

    def trace_upload_timeout(self, file_size):
        """Trace upload timeout"""


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


class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(
        self,
        tracing=VaasTracing(),
        options=VaasOptions(),
        url="wss://gateway-vaas.gdatasecurity.de",
    ):
        self.tracing = tracing
        self.loop_result = None
        self.websocket = None
        self.session_id = None
        self.results = {}
        self.httpx_client: Optional[httpx.AsyncClient] = None
        self.options = options
        self.url = url

    def get_authenticated_websocket(self):
        if self.websocket is None:
            raise VaasInvalidStateError("connect() was not called")
        if not self.websocket.open:
            raise VaasConnectionClosedError(
                "connection closed or connect() was not awaited"
            )
        if self.session_id is None:
            raise VaasConnectionClosedError("connect() was not awaited")
        return self.websocket

    async def connect(self, token, verify=True, websocket=None):
        """Connect to VaaS

        token -- OpenID Connect token signed by a trusted identity provider
        """
        ssl_context = get_ssl_context(self.url, verify)
        if websocket is not None:
            self.websocket = websocket
        else:
            self.websocket = await websockets.client.connect(self.url, ssl=ssl_context)

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
        verdict_response = await self.__for_sha256(sha256)
        return {
            "Sha256": verdict_response.get("sha256"),
            "Guid": verdict_response.get("guid"),
            "Verdict": verdict_response.get("verdict"),
        }

    async def __for_sha256(self, sha256):
        websocket = self.get_authenticated_websocket()
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
        await websocket.send(json.dumps(verdict_request))

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
        websocket = self.get_authenticated_websocket()
        try:
            async for message in websocket:
                vaas_message = json.loads(message)
                if vaas_message.get("kind") == "VerdictResponse":
                    guid = vaas_message.get("guid")
                    future = self.results.get(guid)
                    if future is not None:
                        future.set_result(vaas_message)
        except Exception as error:
            raise VaasConnectionClosedError(error) from error

    async def for_buffer(self, buffer):
        """Returns the verdict for a buffer"""

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(
            None, lambda: hashlib.sha256(buffer).hexdigest()
        )

        verdict_response = await self.__for_sha256(sha256)
        verdict = verdict_response.get("verdict")

        if verdict == "Unknown":
            verdict_response = await self._for_unknown_buffer(
                verdict_response, buffer, len(buffer)
            )

        return {
            "Sha256": verdict_response.get("sha256"),
            "Guid": verdict_response.get("guid"),
            "Verdict": verdict_response.get("verdict"),
        }

    async def _for_unknown_buffer(self, response, buffer, buffer_len):
        start = time.time()
        guid = response.get("guid")
        token = response.get("upload_token")
        url = response.get("url")
        response_message = self.__response_message_for_guid(guid)
        await self.__upload(token, url, buffer, buffer_len)
        try:
            verdict_response = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError as ex:
            self.tracing.trace_upload_result_timeout(buffer_len)
            raise VaasTimeoutError() from ex
        self.tracing.trace_upload_request(time.time() - start, buffer_len)
        return verdict_response

    async def for_file(self, path):
        """Returns the verdict for a file"""

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(None, lambda: hash_file(path))

        verdict_response = await self.__for_sha256(sha256)
        verdict = verdict_response.get("verdict")

        if verdict == "Unknown":
            async with aiofiles.open(path, mode="rb") as file:
                buffer = await file.read()
                verdict_response = await self._for_unknown_buffer(
                    verdict_response, buffer, len(buffer)
                )

        return {
            "Sha256": verdict_response.get("sha256"),
            "Guid": verdict_response.get("guid"),
            "Verdict": verdict_response.get("verdict"),
        }

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
        websocket = self.get_authenticated_websocket()
        start = time.time()
        guid = str(uuid.uuid4())
        verdict_request_for_url = {
            "kind": "VerdictRequestForUrl",
            "url": url,
            "session_id": self.session_id,
            "guid": guid,
            "use_shed": self.options.use_shed,
            "use_cache": self.options.use_cache,
        }
        response_message = self.__response_message_for_guid(guid)
        await websocket.send(json.dumps(verdict_request_for_url))

        try:
            result = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError as ex:
            self.tracing.trace_hash_request_timeout()
            raise VaasTimeoutError() from ex

        self.tracing.trace_url_request(time.time() - start)

        return {
            "Sha256": result.get("sha256"),
            "Guid": result.get("guid"),
            "Verdict": result.get("verdict"),
        }
