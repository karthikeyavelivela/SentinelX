import aiohttp
import asyncio
import logging

logger = logging.getLogger("SentinelX")

async def check_host(session, url):
    try:
        async with session.get(url, timeout=5) as r:
            return url
    except:
        return None


async def find_live_hosts(subdomains):
    logger.info("Checking live hosts")

    alive = []
    async with aiohttp.ClientSession() as session:
        tasks = []

        for sub in subdomains:
            tasks.append(check_host(session, f"https://{sub}"))
            tasks.append(check_host(session, f"http://{sub}"))

        results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                alive.append(r)

    alive = list(set(alive))
    logger.info(f"Live hosts found: {len(alive)}")

    return alive
