from abc import abstractmethod

import httpx

from .options.for_file_options import ForFileOptions
from .options.for_sha256_options import ForSha256Options
from .options.for_stream_options import ForStreamOptions
from .options.for_url_options import ForUrlOptions
from .vaas import VaasVerdict


class VaasInterface:
    @abstractmethod
    async def for_sha256(self, sha256: str, for_sha256_options: ForSha256Options) -> VaasVerdict:
        pass
    @abstractmethod
    async def for_file(self, path: str, for_file_options: ForFileOptions) -> VaasVerdict:
        pass
    @abstractmethod
    async def for_stream(self, stream: httpx.AsyncByteStream, for_stream_options: ForStreamOptions) -> VaasVerdict:
        pass
    @abstractmethod
    async def for_url(self, url: str, for_url_options: ForUrlOptions) -> VaasVerdict:
        pass