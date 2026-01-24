import asyncio
import aiohttp
import logging

logger = logging.getLogger("SentinelX")


async def check_host(session, host):
    try:
        async with session.get(
            host,
            timeout=aiohttp.ClientTimeout(total=8),
            ssl=False
        ) as resp:
            if resp.status < 600:
                return host
    except:
        pass
    return None


async def find_live_hosts(hosts):
    alive = []

    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []

        for host in hosts:
            if not host.startswith("http"):
                host = "https://" + host
            tasks.append(check_host(session, host))

        results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                alive.append(r)

    logger.info(f"Live hosts found: {len(alive)}")
    return alive
