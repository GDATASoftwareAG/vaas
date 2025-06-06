"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
import os.path
import time
import httpx
from urllib.parse import urljoin, urlencode
from importlib.metadata import version

from .async_file_reader import AsyncFileReader
from .authentication.authenticator_interface import AuthenticatorInterface
from .messages.file_analysis_started import FileAnalysisStarted
from .messages.file_report import FileReport
from .messages.url_analysis_request import UrlAnalysisRequest
from .messages.url_analysis_started import UrlAnalysisStarted
from .messages.url_report import UrlReport
from .messages.vaas_verdict import VaasVerdict
from .options.for_file_options import ForFileOptions
from .options.for_sha256_options import ForSha256Options
from .options.for_stream_options import ForStreamOptions
from .options.for_url_options import ForUrlOptions
from .sha256 import SHA256
from .vaas_errors import (
    VaasClientError, VaasServerError, VaasAuthenticationError,
)

TIMEOUT = 60
HTTP2 = False
UPLOAD_TIMEOUT = 600
USER_AGENT = f"Python/{version("gdata-vaas")}"


class VaasTracing:
    """Tracing interface for Vaas"""

    def trace_hash_request(self, elapsed_in_seconds):
        """Trace hash request in seconds"""

    def trace_upload_request(self, elapsed_in_seconds, file_size):
        """Trace upload request in seconds"""

    def trace_url_request(self, elapsed_in_seconds):
        """Trace url request in seconds"""


class VaasOptions:
    """Configure behaviour of VaaS"""

    def __init__(self):
        self.use_cache = True
        self.use_hash_lookup = True


def raise_if_vaas_error_occurred(response):
    if response.is_client_error:
        if response.status_code == 401:
            raise VaasAuthenticationError(response.reason_phrase)
        raise VaasClientError(response.reason_phrase)
    if response.is_server_error:
        raise VaasServerError(response.reason_phrase)


class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(
        self,
        tracing=VaasTracing(),
        options=VaasOptions(),
        authenticator=AuthenticatorInterface(),
        httpx_client = httpx.AsyncClient(http2=HTTP2, verify=True),
        url="https://gateway.production.vaas.gdatasecurity.de",
    ):
        self.tracing = tracing
        self.options = options
        self.httpx_client = httpx_client
        self.authenticator = authenticator
        self.url = url


    async def for_sha256(self, sha256, for_sha256_options=None) -> VaasVerdict:
        if not SHA256.is_valid_sha256(sha256):
            raise VaasClientError("Invalid SHA256")
        for_sha256_options = for_sha256_options or ForSha256Options().from_vaas_config(vaas_options=self.options)
        report_uri = urljoin(self.url + "/", f"files/{sha256}/report" ) + "?" + urlencode({
            "useCache": str(for_sha256_options.use_cache).lower(),
            "useHashLookup": str(for_sha256_options.use_hash_lookup).lower()
        })

        token = await self.authenticator.get_token()
        start = time.time()
        response = await self.httpx_client.get(
            url=report_uri,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": USER_AGENT,
                "tracestate": f"vaasrequestid={for_sha256_options.vaas_request_id}"
            }
        )

        raise_if_vaas_error_occurred(response)

        file_report = FileReport.model_validate(response.json())
        self.tracing.trace_hash_request(time.time() - start)
        return VaasVerdict.from_report(file_report)


    async def for_file(self, path, for_file_options=None) -> VaasVerdict:
        """Returns the verdict for a file"""
        for_file_options = for_file_options or ForFileOptions().from_vaas_config(vaas_options=self.options)

        if for_file_options.use_hash_lookup or for_file_options.use_cache:
            for_sha256_options = ForSha256Options(
                use_cache=for_file_options.use_cache,
                use_hash_lookup=for_file_options.use_hash_lookup,
                vaas_request_id=for_file_options.vaas_request_id
            )

            sha256 = SHA256.hash_file(path)
            response = await self.for_sha256(sha256, for_sha256_options)
            verdict_without_detection = (
                    response.verdict in ["Malicious", "Pup"]
                    and response.detection is None
            )
            if (
                    response.verdict != "Unknown"
                    and not verdict_without_detection
                    and response.fileType is not None
                    and response.mimeType is not None
            ):
                return response

        reader = AsyncFileReader(path)
        for_stream_options = ForStreamOptions(
            vaas_request_id=for_file_options.vaas_request_id,
            use_hash_lookup=for_file_options.use_hash_lookup,
        )
        return await self.for_stream(reader, str(os.path.getsize(path)), for_stream_options)


    async def for_stream(self, async_buffered_reader, content_length, for_stream_options=None) -> VaasVerdict:
        """Returns the verdict for a file"""
        for_stream_options = for_stream_options or ForStreamOptions().from_vaas_config(vaas_options=self.options)
        report_uri = urljoin(self.url + "/", f"files" ) + "?" + urlencode({
            "useHashLookup": str(for_stream_options.use_hash_lookup).lower()
        })

        token = await self.authenticator.get_token()
        start = time.time()
        response = await self.httpx_client.post(
            url=report_uri,
            content=async_buffered_reader,
            headers={
                "Authorization": f"Bearer {token}" ,
                "User-Agent": USER_AGENT,
                "tracestate": f"vaasrequestid={for_stream_options.vaas_request_id}",
                "Content-Length": str(content_length)
            }
        )

        raise_if_vaas_error_occurred(response)

        file_analysis_started = FileAnalysisStarted.model_validate(response.json())
        self.tracing.trace_upload_request(time.time() - start, content_length)
        for_sha256_options = ForSha256Options(
            use_hash_lookup=for_stream_options.use_hash_lookup,
            vaas_request_id=for_stream_options.vaas_request_id
        )

        return await self.for_sha256(file_analysis_started.sha256, for_sha256_options)

    async def for_url(self, url, for_url_options=None) -> VaasVerdict:
        for_url_options = for_url_options or ForUrlOptions().from_vaas_config(vaas_options=self.options)
        token = await self.authenticator.get_token()

        url_analysis_request = UrlAnalysisRequest(
            url=url,
            use_hash_lookup=for_url_options.use_hash_lookup,
        )

        start = time.time()
        response = await self.httpx_client.post(
            url=f"{self.url}/urls",
            content=url_analysis_request.model_dump_json(),
            headers={
                "Authorization": f"Bearer {token}" ,
                "User-Agent": USER_AGENT,
                "tracestate": f"vaasrequestid={for_url_options.vaas_request_id}",
                "Content-Type": "application/json"
            }
        )

        raise_if_vaas_error_occurred(response)

        report_id = UrlAnalysisStarted.model_validate(response.json()).id

        while True:
            response = await self.httpx_client.get(
                url=f"{self.url}/urls/{report_id}/report",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": USER_AGENT,
                    "tracestate": f"vaasrequestid={for_url_options.vaas_request_id}"
                }
            )

            status = response.status_code

            if status == 200:
                self.tracing.trace_url_request(time.time() - start)
                url_report = UrlReport.model_validate(response.json())
                return VaasVerdict.from_report(url_report)
            elif status in {201, 202}:
                continue
            elif status in {400, 403}:
                if status == 401:
                    raise VaasAuthenticationError(response.reason_phrase)
                raise VaasClientError(response.reason_phrase)
            elif 500 <= status < 600:
                raise VaasServerError(response.reason_phrase)
            else:
                raise VaasClientError(f"Unexpected status code {status}: {response.reason_phrase} ")

