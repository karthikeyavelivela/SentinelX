import asyncio
import logging

class Engine:
    def __init__(self, concurrency=20):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = logging.getLogger("SentinelX")

    async def run_task(self, coro):
        async with self.semaphore:
            try:
                return await coro
            except Exception as e:
                self.logger.error(f"Task failed: {e}")

    async def run(self, tasks):
        return await asyncio.gather(
            *[self.run_task(task) for task in tasks]
        )
