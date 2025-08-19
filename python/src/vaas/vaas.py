"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""
from json import JSONDecodeError
import os.path
import time
import httpx
from urllib.parse import urljoin, urlencode
from importlib.metadata import PackageNotFoundError, version

from pydantic import ValidationError

from .messages.problem_details import ProblemDetails

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
try:
    VERSION = version("gdata-vaas")
except PackageNotFoundError:
    VERSION = "0.0.0"
USER_AGENT = f"Python/{VERSION}"


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
        self.timeout = 300


def raise_if_vaas_error_occurred(response):
    if not response.is_success:
        try:
            json = response.json()
            if response.is_client_error:
                if response.status_code == 401:
                    raise VaasAuthenticationError(ProblemDetails.model_validate(json))
                raise VaasClientError(ProblemDetails.model_validate(json))
            if response.is_server_error:
                raise VaasServerError(ProblemDetails.model_validate(json))
            else:
                raise VaasClientError(f"Unexpected status code {response.status_code}: {response.reason_phrase} ")
        except (JSONDecodeError, ValidationError):
            raise VaasServerError(f"Server error {response.status_code}: {response.reason_phrase}")

def get_request_headers(request_id=None, token=None):
    if request_id is not None:
        return {
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "tracestate": f"vaasrequestid={request_id}",
        }
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
    }

class Vaas:
    """Verdict-as-a-Service client"""

    def __init__(
        self,
        tracing=None,
        options=None,
        authenticator=None,
        httpx_client=None,
        url="https://gateway.production.vaas.gdatasecurity.de",
    ):
        self.tracing = tracing or VaasTracing()
        self.options = options or VaasOptions()
        self.authenticator = authenticator or AuthenticatorInterface()
        self.httpx_client = httpx_client or httpx.AsyncClient(http2=HTTP2, verify=True)
        self.url = url


    async def for_sha256(self, sha256, for_sha256_options=None) -> VaasVerdict:
        if not SHA256.is_valid_sha256(sha256):
            raise VaasClientError("Invalid SHA256")
        for_sha256_options = for_sha256_options or ForSha256Options().from_vaas_config(vaas_options=self.options)
        report_uri = urljoin(self.url + "/", f"files/{sha256}/report" ) + "?" + urlencode({
            "useCache": str(for_sha256_options.use_cache).lower(),
            "useHashLookup": str(for_sha256_options.use_hash_lookup).lower()
        })

        while True:
            token = await self.authenticator.get_token()
            headers = get_request_headers(for_sha256_options.vaas_request_id, token=token)
            start = time.time()
            response = await self.httpx_client.get(
                url=report_uri,
                headers=headers,
                timeout=self.options.timeout
            )

            raise_if_vaas_error_occurred(response)

            status = response.status_code

            if status == 200:
                self.tracing.trace_url_request(time.time() - start)
                file_report = FileReport.model_validate(response.json())
                return VaasVerdict.from_report(file_report)
            elif status in {201, 202}:
                continue

            self.tracing.trace_hash_request(time.time() - start)

    async def for_file(self, path, for_file_options=None) -> VaasVerdict:
        """Returns the verdict for a file"""
        for_file_options = for_file_options or ForFileOptions().from_vaas_config(vaas_options=self.options)

        response = None
        if for_file_options.use_hash_lookup or for_file_options.use_cache:
            for_sha256_options = ForSha256Options(
                use_cache=for_file_options.use_cache,
                use_hash_lookup=for_file_options.use_hash_lookup,
                vaas_request_id=for_file_options.vaas_request_id
            )

            sha256 = await SHA256.hash_file(path)
            try:
                response = await self.for_sha256(sha256, for_sha256_options)
            except (VaasClientError, VaasServerError, VaasAuthenticationError):
                response = None

            verdict_without_detection = (
                    response
                    and response.verdict in ["Malicious", "Pup"]
                    and response.detection is None
            )
            if (
                    response
                    and response.verdict != "Unknown"
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
        return await self.for_stream(reader, os.path.getsize(path), for_stream_options)


    async def for_stream(self, async_buffered_reader, content_length, for_stream_options=None) -> VaasVerdict:
        """Returns the verdict for a file"""
        for_stream_options = for_stream_options or ForStreamOptions().from_vaas_config(vaas_options=self.options)
        report_uri = urljoin(self.url + "/", "files" ) + "?" + urlencode({
            "useHashLookup": str(for_stream_options.use_hash_lookup).lower()
        })

        token = await self.authenticator.get_token()
        headers = get_request_headers(for_stream_options.vaas_request_id, token=token)
        headers["Content-Length"] = str(content_length)
        start = time.time()
        response = await self.httpx_client.post(
            url=report_uri,
            content=async_buffered_reader,
            headers=headers,
            timeout=self.options.timeout
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

        headers = get_request_headers(for_url_options.vaas_request_id, token=token)
        headers["Content-Type"] = "application/json"
        start = time.time()
        response = await self.httpx_client.post(
            url=urljoin(self.url + "/", "urls"),
            content=url_analysis_request.model_dump_json(),
            headers=headers,
            timeout=self.options.timeout
        )

        raise_if_vaas_error_occurred(response)

        report_id = UrlAnalysisStarted.model_validate(response.json()).id

        while True:
            token = await self.authenticator.get_token()
            headers = get_request_headers(for_url_options.vaas_request_id, token=token)
            headers.pop("Content-Type", None)
            response = await self.httpx_client.get(
                url=urljoin(self.url + "/", f"urls/{report_id}/report"),
                headers=headers,
                timeout=self.options.timeout
            )

            status = response.status_code

            if status == 200:
                self.tracing.trace_url_request(time.time() - start)
                url_report = UrlReport.model_validate(response.json())
                return VaasVerdict.from_report(url_report)
            elif status in {201, 202}:
                continue

            raise_if_vaas_error_occurred(response)
