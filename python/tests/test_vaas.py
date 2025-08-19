# pylint: disable=C0114,C0116,C0115
import asyncio
import os
from unittest.mock import AsyncMock
import httpx
import pytest
from dotenv import load_dotenv

from src.vaas.vaas import VaasAuthenticationError
from src.vaas.options.for_file_options import ForFileOptions
from src.vaas.options.for_sha256_options import ForSha256Options
from src.vaas.options.for_stream_options import ForStreamOptions
from src.vaas.options.for_url_options import ForUrlOptions
from src.vaas.vaas_errors import VaasClientError, VaasServerError

load_dotenv()

VAAS_URL = os.getenv("VAAS_URL")

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
CLEAN_SHA256 = "d24dc598b54a8eedb0a4b381fad68af956441dffa9c9d5d9ac81de73fcc0a089"
PUP_SHA256 = "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad"

EICAR_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/eicar.com.txt"
CLEAN_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
PUP_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/PotentiallyUnwanted.exe"

CLEAN_FILE_CONTENT = "I am clean."


class TestVaas:
    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "sha256, expected_verdict",
        [
            (EICAR_SHA256, "Malicious"),
            (CLEAN_SHA256, "Clean"),
            (PUP_SHA256, "Pup")
        ],
        ids=["Malware", "Clean", "Pup"]
    )
    async def test_for_sha256_returns_verdict(self, vaas, sha256, expected_verdict):
            verdict = await vaas.for_sha256(sha256)

            assert verdict.verdict == expected_verdict
            assert verdict.sha256.casefold() == sha256.casefold()

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "use_cache, use_hash_lookup",
        [
            (False, False),
            (False, True),
            (True, False),
            (True, True),
        ],
        ids=["false_for_all", "only_hash_lookup", "only_cache", "true_for_all"]
    )
    async def test_for_sha256_send_options(self, vaas, use_cache, use_hash_lookup, httpx_mock):
        request_url = f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(use_cache).lower()}&useHashLookup={str(use_hash_lookup).lower()}"
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        options = ForSha256Options(use_cache=use_cache, use_hash_lookup=use_hash_lookup)
        verdict = await vaas.for_sha256(CLEAN_SHA256, options)

        actual_request = httpx_mock.get_requests()[0]
        actual_url = str(actual_request.url)
        assert len(httpx_mock.get_requests()) == 1
        assert actual_url == request_url, f"URL mismatch:\nExpected: {request_url}\nActual:   {actual_url}"
        assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    async def test_for_sha256_send_user_agent(self, vaas, httpx_mock):
        request_url = f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}"
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        verdict = await vaas.for_sha256(CLEAN_SHA256)

        request = httpx_mock.get_requests()[0]
        assert len(httpx_mock.get_requests()) == 1
        assert "Python" in request.headers["User-Agent"]
        assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    async def test_for_sha256_set_request_id_send_trace_state(self, vaas, httpx_mock):
        request_url = f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}"
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        options = ForSha256Options(vaas_request_id="foobar")
        verdict = await vaas.for_sha256(CLEAN_SHA256, options)

        request = httpx_mock.get_requests()[0]
        assert len(httpx_mock.get_requests()) == 1
        assert "vaasrequestid=foobar" in request.headers["tracestate"]
        assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    async def test_for_sha256_bad_request_raise_vaas_client_error(self, vaas, httpx_mock):
        request_url = (f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}"
        )
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=400,
            json = {
                "detail": "Mocked client-side error",
                "type": "VaasClientException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasClientError) as exception_info:
            await vaas.for_sha256(CLEAN_SHA256)

        problem_details = exception_info.value.args[0]
        assert problem_details.detail == "Mocked client-side error"
        assert problem_details.type == "VaasClientException"

    @pytest.mark.asyncio()
    async def test_for_sha256_server_error_raise_vaas_server_error(self, vaas, httpx_mock):
        request_url = (f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}"
        )
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=500,
            json = {
                "detail": "Mocked server-side error",
                "type": "VaasServerException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasServerError) as exception_info:
            await vaas.for_sha256(CLEAN_SHA256)

        problem_details = exception_info.value.args[0]
        assert problem_details.detail == "Mocked server-side error"
        assert problem_details.type == "VaasServerException"

    @pytest.mark.asyncio()
    async def test_for_sha256_authentication_error_raise_vaas_authentication_error(self, vaas):
        vaas.authenticator.get_token = AsyncMock(side_effect=VaasAuthenticationError("Mocked auth error"))

        with pytest.raises(VaasAuthenticationError):
            await vaas.for_sha256(CLEAN_SHA256)

    @pytest.mark.asyncio()
    async def test_for_sha256_unauthorized_raise_vaas_authentication_error(self, vaas, httpx_mock):
        request_url = (f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}"
        )
        httpx_mock.add_response(
            method="GET",
            url=request_url,
            status_code=401,
            json = {
                "detail": "Authentication error",
                "type": "VaasAuthenticationException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasAuthenticationError) as exception_info:
            await vaas.for_sha256(CLEAN_SHA256)

        problem_details = exception_info.value.args[0]
        assert problem_details.detail == "Authentication error"
        assert problem_details.type == "VaasAuthenticationException"

    @pytest.mark.asyncio()
    async def test_for_sha256_cancel_request_raise_cancel_error(self, vaas, httpx_mock):
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")
        httpx_mock.add_exception(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            exception=asyncio.CancelledError()
        )

        with pytest.raises(asyncio.CancelledError):
            await vaas.for_sha256(CLEAN_SHA256)

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "url, expected_verdict",
        [
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/eicar.com.txt", "Malicious"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt", "Clean"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/PotentiallyUnwanted.exe", "Pup")
        ],
        ids=["Malware", "Clean", "Pup"]
    )
    async def test_for_stream_returns_verdict(self, vaas, url, expected_verdict):
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                content_length = response.headers["Content-Length"]
                verdict = await vaas.for_stream(response.aiter_bytes(), content_length)

                assert verdict.verdict == expected_verdict

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize(
        "use_hash_lookup",
        [
            False,
            True
        ],
        ids=["hash_lookup_enabled", "hash_lookup_disabled"]
    )
    async def test_for_stream_send_options(self, vaas, use_hash_lookup, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(use_hash_lookup).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )
        httpx_mock.add_response(
            method="GET",
            url= f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(use_hash_lookup).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]

            options = ForStreamOptions(use_hash_lookup=use_hash_lookup)
            verdict = await vaas.for_stream(response.aiter_bytes(), content_length, options)

            for actual_request in httpx_mock.get_requests():
                actual_url = str(actual_request.url)

            assert len(httpx_mock.get_requests()) == 2
            assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_send_user_agent(self, vaas, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )
        httpx_mock.add_response(
            method="GET",
            url= f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            verdict = await vaas.for_stream(response.aiter_bytes(), content_length)
            for request in httpx_mock.get_requests():
                assert "Python" in request.headers["User-Agent"]

            assert len(httpx_mock.get_requests()) == 2
            assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_set_request_id_send_trace_state(self, vaas, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )
        httpx_mock.add_response(
            method="GET",
            url= f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(True).lower()}&useHashLookup={str(True).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            options = ForStreamOptions(vaas_request_id="foobar")
            verdict = await vaas.for_stream(response.aiter_bytes(), content_length, options)
            for request in httpx_mock.get_requests():
                assert "vaasrequestid=foobar" in request.headers["tracestate"]

            assert len(httpx_mock.get_requests()) == 2
            assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_bad_request_raise_vaas_client_error(self, vaas, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=400,
            json = {
                "detail": "Mocked client-side error",
                "type": "VaasClientException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            with pytest.raises(VaasClientError) as exception_info:
                await vaas.for_stream(response.aiter_bytes(), content_length)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Mocked client-side error"
            assert problem_details.type == "VaasClientException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_server_error_raise_vaas_server_error(self, vaas, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=500,
            json = {
                "detail": "Mocked server-side error",
                "type": "VaasServerException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            with pytest.raises(VaasServerError) as exception_info:
                await vaas.for_stream(response.aiter_bytes(), content_length)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Mocked server-side error"
            assert problem_details.type == "VaasServerException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_authentication_error_raise_vaas_authentication_error(self, vaas, httpx_mock):
        vaas.authenticator.get_token = AsyncMock(side_effect=VaasAuthenticationError("Mocked auth error"))

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            with pytest.raises(VaasAuthenticationError):
                await vaas.for_stream(response.aiter_bytes(), content_length)

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_unauthorized_raise_vaas_authentication_error(self, vaas, httpx_mock):
        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=401,
            json = {
                "detail": "Authentication error",
                "type": "VaasAuthenticationException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            with pytest.raises(VaasAuthenticationError) as exception_info:
                await vaas.for_stream(response.aiter_bytes(), content_length)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Authentication error"
            assert problem_details.type == "VaasAuthenticationException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_stream_cancel_request_raise_cancel_error(self, vaas, httpx_mock):
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")
        httpx_mock.add_exception(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            exception=asyncio.CancelledError()
        )

        async with httpx.AsyncClient() as client:
            response = await client.get("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt")
            content_length = response.headers["Content-Length"]
            with pytest.raises(asyncio.CancelledError):
                await vaas.for_stream(response.aiter_bytes(), content_length)


    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "url, expected_verdict",
        [
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/eicar.com.txt", "Malicious"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt", "Clean"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/PotentiallyUnwanted.exe", "Pup")
        ],
        ids=["Malware", "Clean", "Pup"]
    )
    async def test_for_file_returns_verdict(self, vaas, url, expected_verdict):
            async with httpx.AsyncClient() as client:
                filename = os.path.join("/tmp", os.path.basename(url))
                response = await client.get(url)
                response.raise_for_status()
                with open(filename, mode="wb") as file:
                    file.write(response.content)
                verdict = await vaas.for_file(filename)

                assert verdict.verdict == expected_verdict

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize(
        ("use_cache", "use_hash_lookup", "request_count"),
        [
            (False, False, 2),
            (False, True, 3),
            (True, False, 3),
            (True, True, 3),
        ],
        ids=["false_for_all", "only_hash_lookup", "only_cache", "true_for_all"]
    )
    async def test_for_file_send_options(self, vaas, use_cache, use_hash_lookup, request_count, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache={str(use_cache).lower()}&useHashLookup={str(use_hash_lookup).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            },
            is_optional=True
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup={str(use_hash_lookup).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/files?useHashLookup={str(use_hash_lookup).lower()}",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

        options = ForFileOptions(use_cache=use_cache, use_hash_lookup=use_hash_lookup)
        verdict = await vaas.for_file(filename, options)

        assert verdict.verdict == "Clean"
        assert len(httpx_mock.get_requests()) == request_count

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_send_user_agent(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            },
            is_reusable=True
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/files?useHashLookup=true",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

        verdict = await vaas.for_file(filename)
        for request in httpx_mock.get_requests():
            assert "Python" in request.headers["User-Agent"]

        assert verdict.verdict == "Clean"
        assert len(httpx_mock.get_requests()) == 3

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_set_request_id_send_trace_state(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "detection": None,
                "fileType": None,
                "mimeType": None
            },
            is_reusable=True
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/files?useHashLookup=true",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            options = ForFileOptions(vaas_request_id="foobar")
            verdict = await vaas.for_file(filename, options)
            for request in httpx_mock.get_requests():
                assert "vaasrequestid=foobar" in request.headers["tracestate"]

            assert len(httpx_mock.get_requests()) == 3
            assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_bad_request_raise_vaas_client_error(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            status_code=400,
            json = {
                "detail": "Mocked client-side error",
                "type": "VaasClientException"
            }
        )

        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=400,
            json = {
                "detail": "Mocked client-side error",
                "type": "VaasClientException"
            }
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            with pytest.raises(VaasClientError) as exception_info:
                await vaas.for_file(filename)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Mocked client-side error"
            assert problem_details.type == "VaasClientException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_server_error_raise_vaas_server_error(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            status_code=500,
            json = {
                "detail": "Mocked server-side error",
                "type": "VaasServerException"
            }
        )

        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=500,
            json = {
                "detail": "Mocked server-side error",
                "type": "VaasServerException"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            with pytest.raises(VaasServerError) as exception_info:
                await vaas.for_file(filename)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Mocked server-side error"
            assert problem_details.type == "VaasServerException"

    @pytest.mark.asyncio()
    async def test_for_file_authentication_error_raise_vaas_authentication_error(self, vaas):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        vaas.authenticator.get_token = AsyncMock(side_effect=VaasAuthenticationError("Mocked auth error"))

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            with pytest.raises(VaasAuthenticationError):
                await vaas.for_sha256(CLEAN_SHA256)

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_unauthorized_raise_vaas_authentication_error(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            status_code=401,
            json={
                "detail": "Authentication error",
                "type": "VaasAuthenticationException"
            }
        )

        httpx_mock.add_response(
            method="POST",
            url= f"{VAAS_URL}/files?useHashLookup={str(True).lower()}",
            status_code=401,
            json = {
                "detail": "Authentication error",
                "type": "VaasAuthenticationException"
            }
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            with pytest.raises(VaasAuthenticationError) as exception_info:
                await vaas.for_file(filename)

            problem_details = exception_info.value.args[0]
            assert problem_details.detail == "Authentication error"
            assert problem_details.type == "VaasAuthenticationException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_file_cancel_request_raise_cancel_error(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        filename = os.path.join("/tmp", os.path.basename(url))

        httpx_mock.add_exception(
            method="GET",
            url=f"{VAAS_URL}/files/{CLEAN_SHA256}/report?useCache=true&useHashLookup=true",
            exception=asyncio.CancelledError()
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(filename, mode="wb") as file:
                file.write(response.content)

            with pytest.raises(asyncio.CancelledError):
                await vaas.for_file(filename)

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "url, expected_verdict",
        [
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/eicar.com.txt", "Malicious"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt", "Clean"),
            ("https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/PotentiallyUnwanted.exe", "Pup")
        ],
        ids=["Malware", "Clean", "Pup"]
    )
    async def test_for_url_returns_verdict(self, vaas, url, expected_verdict):
        verdict = await vaas.for_url(url)

        assert verdict.verdict == expected_verdict

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize(
        "use_hash_lookup",
        [
            False,
            True
        ],
        ids=["hash_lookup_enabled", "hash_lookup_disabled"]
    )
    async def test_for_url_send_options(self, vaas, use_hash_lookup, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/urls/foobar/report",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "url": url,
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/urls",
            status_code=200,
            json={
                "id": "foobar"
            }
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        options = ForUrlOptions(use_hash_lookup=use_hash_lookup)
        verdict = await vaas.for_url(url, options)

        assert verdict.verdict == "Clean"
        assert len(httpx_mock.get_requests()) == 2

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_url_send_user_agent(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/urls/foobar/report",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "url": url,
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/urls",
            status_code=200,
            json={
                "id": "foobar"
            }
        )
        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        verdict = await vaas.for_url(url)
        for request in httpx_mock.get_requests():
            assert "Python" in request.headers["User-Agent"]


        assert verdict.verdict == "Clean"
        assert len(httpx_mock.get_requests()) == 2

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_url_set_request_id_send_trace_state(self, vaas, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        httpx_mock.add_response(
            method="GET",
            url=f"{VAAS_URL}/urls/foobar/report",
            status_code=200,
            json={
                "sha256": CLEAN_SHA256,
                "verdict": "Clean",
                "url": url,
                "detection": None,
                "fileType": None,
                "mimeType": None
            }
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{VAAS_URL}/urls",
            status_code=200,
            json={
                "id": "foobar"
            }
        )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        options = ForUrlOptions(vaas_request_id="foobar")
        verdict = await vaas.for_url(url, options)
        for request in httpx_mock.get_requests():
            assert "vaasrequestid=foobar" in request.headers["tracestate"]

        assert len(httpx_mock.get_requests()) == 2
        assert verdict.verdict == "Clean"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize("post_fails", [True, False], ids=["post_400", "get_400"])
    async def test_for_url_bad_request_raise_vaas_client_error(self, vaas, httpx_mock, post_fails):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        if post_fails:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=400,
                json={
                    "detail": "Mocked client-side error (POST)",
                    "type": "VaasClientException"
                },
                is_optional=True
            )
        else:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=200,
                json={
                    "id": "foobar"
                },
                is_optional = True
            )

            httpx_mock.add_response(
                method="GET",
                url=f"{VAAS_URL}/urls/foobar/report",
                status_code=400,
                json={
                    "detail": "Mocked client-side error (GET)",
                    "type": "VaasClientException"
                },
                is_optional=True
            )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasClientError) as exception_info:
            await vaas.for_url(url)

        problem_details = exception_info.value.args[0]
        assert "Mocked client-side error" in problem_details.detail
        assert problem_details.type == "VaasClientException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize("post_fails", [True, False], ids=["post_500", "get_500"])
    async def test_for_url_server_error_raise_vaas_server_error(self, vaas, httpx_mock, post_fails):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        if post_fails:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=500,
                json={
                    "detail": "Mocked server-side error (POST)",
                    "type": "VaasServerException"
                },
                is_optional=True
            )
        else:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=200,
                json={
                    "id": "foobar"
                },
                is_optional = True
            )

            httpx_mock.add_response(
                method="GET",
                url=f"{VAAS_URL}/urls/foobar/report",
                status_code=500,
                json={
                    "detail": "Mocked server-side error (GET)",
                    "type": "VaasServerException"
                },
                is_optional=True
            )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasServerError) as exception_info:
            await vaas.for_url(url)

        problem_details = exception_info.value.args[0]
        assert "Mocked server-side error" in problem_details.detail
        assert problem_details.type == "VaasServerException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    async def test_for_url_authentication_error_raise_vaas_authentication_error(self, vaas):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"
        vaas.authenticator.get_token = AsyncMock(side_effect=VaasAuthenticationError("Mocked auth error"))
        with pytest.raises(VaasAuthenticationError):
            await vaas.for_url(url)

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize("post_fails", [True, False], ids=["post_401", "get_401"])
    async def test_for_url_unauthorized_raise_vaas_authentication_error(self, vaas, post_fails, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        if post_fails:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=401,
                json={
                    "detail": "Authentication error",
                    "type": "VaasAuthenticationException"
                },
                is_optional=True
            )
        else:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=200,
                json={
                    "id": "foobar"
                },
                is_optional = True
            )

            httpx_mock.add_response(
                method="GET",
                url=f"{VAAS_URL}/urls/foobar/report",
                status_code=401,
                json={
                    "detail": "Authentication error",
                    "type": "VaasAuthenticationException"
                },
                is_optional=True
            )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(VaasAuthenticationError) as exception_info:
            await vaas.for_url(url)

        problem_details = exception_info.value.args[0]
        assert problem_details.detail == "Authentication error"
        assert problem_details.type == "VaasAuthenticationException"

    @pytest.mark.asyncio()
    @pytest.mark.httpx_mock(should_mock=lambda request: "gdatasecurity.de" in request.url.host)
    @pytest.mark.parametrize("post_fails", [True, False], ids=["post_cancel", "get_cancel"])
    async def test_for_url_cancel_request_raise_cancel_error(self, vaas, post_fails, httpx_mock):
        url = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt"

        if post_fails:
            httpx_mock.add_exception(
                method="POST",
                url=f"{VAAS_URL}/urls",
                exception=asyncio.CancelledError(),
                is_optional = True
            )
        else:
            httpx_mock.add_response(
                method="POST",
                url=f"{VAAS_URL}/urls",
                status_code=200,
                json={
                    "id": "foobar"
                },
                is_optional = True
            )

            httpx_mock.add_exception(
                method="GET",
                url=f"{VAAS_URL}/urls/foobar/report",
                exception=asyncio.CancelledError(),
                is_optional = True
            )

        vaas.authenticator.get_token = AsyncMock(return_value="mocked-token")

        with pytest.raises(asyncio.CancelledError):
            await vaas.for_url(url)
