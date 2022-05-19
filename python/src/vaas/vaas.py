"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
import hashlib
import json
import time
import uuid
import asyncio
from asyncio import Future
from jwt import JWT
import requests
import websockets.client

URL = "wss://gateway-vaas.gdatasecurity.de"

class VaasTracing:
    """Tracing interface for Vaas"""

    def trace_hash_request(self, elapsed_in_seconds):
        """Trace hash request in seconds"""

    def trace_upload_request(self, elapsed_in_seconds):
        """Trace upload request in seconds"""


class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(self, tracing=VaasTracing()):
        self.tracing = tracing
        self.loop_result = None
        self.websocket = None
        self.session_id = None
        self.results = {}
        self.session = requests.Session()

    async def connect(self, token, url=URL):
        """Connect to VaaS

        token -- a OpenID Connect token signed by a trusted identity provider
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

    async def close(self):
        """Close the connection"""
        if self.websocket is not None:
            await self.websocket.close()
        if self.loop_result is not None:
            await self.loop_result

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
        }
        response_message = self.__response_message_for_guid(guid)
        await self.websocket.send(json.dumps(verdict_request))
        response_message.add_done_callback(
            lambda _: self.tracing.trace_hash_request(time.time() - start)
        )
        return await response_message

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
        sha256 = hashlib.sha256(buffer).hexdigest()
        response = await self.__for_sha256(sha256)
        verdict = response.get("verdict")

        if verdict == "Unknown":
            guid = response.get("guid")
            token = response.get("upload_token")
            url = response.get("url")
            response_message = self.__response_message_for_guid(guid)
            self.__upload(token, url, buffer)
            verdict = (await response_message).get("verdict")
            response_message.add_done_callback(
                lambda _: self.tracing.trace_upload_request(time.time() - start)
            )

        return verdict

    async def for_file(self, path):
        """Returns the verdict for a file"""
        with open(path, "rb") as open_file:
            return await self.for_buffer(open_file.read())

    def __upload(self, token, upload_uri, buffer):
        jwt = JWT()
        decoded_token = jwt.decode(token, do_verify=False)
        trace_id = decoded_token.get("traceId")
        self.session.put(
            url=upload_uri,
            data=buffer,
            headers={"Authorization": token, "traceParent": trace_id},
        )
