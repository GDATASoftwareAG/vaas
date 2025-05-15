"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
import hashlib
import json
import time
import uuid
from typing import Optional, TypedDict, Literal
import asyncio
from asyncio import Future
import ssl
from urllib.parse import urlparse
import aiofiles
from jwt import PyJWT
import httpx
import websockets.client
from .vaas_errors import (
    VaasInvalidStateError,
    VaasConnectionClosedError,
    VaasTimeoutError, VaasClientError, VaasServerError,
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
        self.use_hash_lookup = True

class VaasVerdict(TypedDict):
    Sha256: str
    "The SHA256 hash of the file"

    Guid: str

    Verdict: Literal["Clean", "Malicious", "Unknown", "Pup"]
    
    Detection: Optional[str]
    "Name of the detected malware if found"
    
    FileType: Optional[str]
    "The file type of the file"

    MimeType: Optional[str]
    "The mime type of the file"

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


def problem_details_to_error(problem_details):
    type = problem_details.get("type")
    details = problem_details.get("details")
    if type == "VaasClientException":
        return VaasClientError(details)
    return VaasServerError(details)


def map_response(verdict_response) -> VaasVerdict:
    return {
        "Sha256": verdict_response.get("sha256"),
        "Guid": verdict_response.get("guid"),
        "Verdict": verdict_response.get("verdict"),
        "Detection": verdict_response.get("detection"),
        "FileType": verdict_response.get("file_type"),
        "MimeType": verdict_response.get("mime_type")
    }

def raiseIfHttpResponseError(response):
    if response.is_server_error:
        raise VaasServerError(response.reason_phrase)
    if response.is_client_error:
        raise VaasClientError(response.reason_phrase)

class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(
        self,
        tracing=VaasTracing(),
        options=VaasOptions(),
        url="wss://gateway.production.vaas.gdatasecurity.de",
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
        """Get authenticated websocket"""
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

    async def for_sha256(self, sha256, verdict_request_attributes=None, guid=None) -> VaasVerdict:
        """Returns the verdict for a SHA256 checksum"""
        verdict_response = await self.__for_sha256(
            sha256, verdict_request_attributes, guid
        )
        return map_response(verdict_response)

    async def __for_stream(self, verdict_request_attributes=None, guid=None):
        if verdict_request_attributes is not None and not isinstance(
            verdict_request_attributes, dict
        ):
            raise TypeError("verdict_request_attributes has to be dict(str, str)")

        websocket = self.get_authenticated_websocket()
        start = time.time()
        guid = guid or str(uuid.uuid4())
        verdict_request = {
            "kind": "VerdictRequestForStream",
            "session_id": self.session_id,
            "guid": guid,
            "use_hash_lookup": self.options.use_hash_lookup,
            "use_cache": self.options.use_cache,
            "verdict_request_attributes": verdict_request_attributes,
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

    async def __for_sha256(self, sha256, verdict_request_attributes=None, guid=None):
        if verdict_request_attributes is not None and not isinstance(
            verdict_request_attributes, dict
        ):
            raise TypeError("verdict_request_attributes has to be dict(str, str)")

        websocket = self.get_authenticated_websocket()
        start = time.time()
        guid = guid or str(uuid.uuid4())
        verdict_request = {
            "kind": "VerdictRequest",
            "sha256": sha256,
            "session_id": self.session_id,
            "guid": guid,
            "use_hash_lookup": self.options.use_hash_lookup,
            "use_cache": self.options.use_cache,
            "verdict_request_attributes": verdict_request_attributes,
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
        try:
            websocket = self.get_authenticated_websocket()
        except VaasConnectionClosedError as e:
            # Fix for Python >= 3.12: Connection has already been closed again. End loop.
            return
        try:
            async for message in websocket:
                vaas_message = json.loads(message)
                message_kind = vaas_message.get("kind")
                guid = vaas_message.get("guid")
                if message_kind == "VerdictResponse":
                    future = self.results.get(guid)
                    if future is not None:
                        future.set_result(vaas_message)
                if message_kind == "Error":
                    problem_details = vaas_message.get("problem_details")
                    if guid is None or problem_details is None:
                        # Error: Server sent guid we are not waiting for, or problem details are null, ignore it
                        continue
                    future = self.results.get(guid)
                    if future is not None:
                        future.set_exception(problem_details_to_error(problem_details))
        except Exception as error:
            raise VaasConnectionClosedError(error) from error

    async def for_buffer(self, buffer, verdict_request_attributes=None, guid=None) -> VaasVerdict:
        """Returns the verdict for a buffer"""

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(
            None, lambda: hashlib.sha256(buffer).hexdigest()
        )

        verdict_response = await self.__for_sha256(
            sha256, verdict_request_attributes, guid
        )
        verdict = verdict_response.get("verdict")

        if verdict == "Unknown":
            verdict_response = await self._for_unknown_buffer(
                verdict_response, buffer, len(buffer)
            )

        return map_response(verdict_response)

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

    async def for_stream(self, asyncBufferedReader, len, verdict_request_attributes=None, guid=None) -> VaasVerdict:
        """Returns the verdict for a file"""

        verdict_response = await self.__for_stream(
            verdict_request_attributes, guid
        )
        guid = verdict_response.get("guid")
        token = verdict_response.get("upload_token")
        url = verdict_response.get("url")
        verdict = verdict_response.get("verdict")

        if verdict != "Unknown":
            raise VaasServerError("server returned verdict without receiving content")

        if token == None:
            raise VaasServerError("VerdictResponse missing UploadToken for stream upload")

        if url == None:
            raise VaasServerError("VerdictResponse missing URL for stream upload")

        start = time.time()
        response_message = self.__response_message_for_guid(guid)
        await self.__upload(token, url, asyncBufferedReader, len)
        try:
            verdict_response = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError as ex:
            self.tracing.trace_upload_result_timeout(len)
            raise VaasTimeoutError() from ex
        self.tracing.trace_upload_request(time.time() - start, len)

        return map_response(verdict_response)

    async def for_file(self, path, verdict_request_attributes=None, guid=None) -> VaasVerdict:
        """Returns the verdict for a file"""

        loop = asyncio.get_running_loop()
        sha256 = await loop.run_in_executor(None, lambda: hash_file(path))

        verdict_response = await self.__for_sha256(
            sha256, verdict_request_attributes, guid
        )
        verdict = verdict_response.get("verdict")

        if verdict == "Unknown":
            async with aiofiles.open(path, mode="rb") as file:
                buffer = await file.read()
                verdict_response = await self._for_unknown_buffer(
                    verdict_response, buffer, len(buffer)
                )

        return map_response(verdict_response)

    async def __upload(self, token, upload_uri, buffer_or_file, content_length):
        jwt = PyJWT()
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        try:
            response = await self.httpx_client.put(
                url=upload_uri,
                content=buffer_or_file,
                headers={
                    "Authorization": token,
                    "Content-Length": str(content_length),
                },
                timeout=UPLOAD_TIMEOUT,
            )
            raiseIfHttpResponseError(response)
        except httpx.TimeoutException as ex:
            self.tracing.trace_upload_timeout(content_length)
            raise VaasTimeoutError() from ex

    async def for_url(self, url, verdict_request_attributes=None, guid=None) -> VaasVerdict:
        """Returns the verdict for a file from an url"""
        if verdict_request_attributes is not None and not isinstance(
            verdict_request_attributes, dict
        ):
            raise TypeError("verdict_request_attributes has to be dict(str, str)")

        websocket = self.get_authenticated_websocket()
        start = time.time()
        guid = guid or str(uuid.uuid4())
        verdict_request_for_url = {
            "kind": "VerdictRequestForUrl",
            "url": url,
            "session_id": self.session_id,
            "guid": guid,
            "use_hash_lookup": self.options.use_hash_lookup,
            "use_cache": self.options.use_cache,
            "verdict_request_attributes": verdict_request_attributes,
        }
        response_message = self.__response_message_for_guid(guid)
        await websocket.send(json.dumps(verdict_request_for_url))

        try:
            result = await asyncio.wait_for(response_message, timeout=TIMEOUT)
        except asyncio.TimeoutError as ex:
            self.tracing.trace_hash_request_timeout()
            raise VaasTimeoutError() from ex

        self.tracing.trace_url_request(time.time() - start)

        return map_response(result)
