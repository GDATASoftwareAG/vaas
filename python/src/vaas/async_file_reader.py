import asyncio

class AsyncFileReader:
    def __init__(self, path, chunk_size=8192):
        self.path = path
        self.chunk_size = chunk_size

    async def __aiter__(self):
        loop = asyncio.get_event_loop()
        with open(self.path, "rb") as f:
            while True:
                chunk = await loop.run_in_executor(None, f.read, self.chunk_size)
                if not chunk:
                    break
                yield chunk
