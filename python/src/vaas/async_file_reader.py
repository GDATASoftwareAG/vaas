import aiofiles

class AsyncFileReader:
    def __init__(self, path, chunk_size=8192):
        self.path = path
        self.chunk_size = chunk_size

    async def __aiter__(self):
        async with aiofiles.open(self.path, "rb") as f:
            while True:
                chunk = await f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk
