import hashlib
import re

class SHA256:
    @staticmethod
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

    @staticmethod
    def is_valid_sha256(hashsum):
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", hashsum))