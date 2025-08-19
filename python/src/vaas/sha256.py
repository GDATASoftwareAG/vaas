import hashlib
import re

from .async_file_reader import AsyncFileReader

class SHA256:
    @staticmethod
    async def hash_file(filename):
        """Return sha256 hash for file"""
        block_size = 65536

        h_sha256 = hashlib.sha256()

        reader = AsyncFileReader(filename)
        async for chunk in reader:
            h_sha256.update(chunk)

        return h_sha256.hexdigest()

    @staticmethod
    def is_valid_sha256(hashsum):
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", hashsum))