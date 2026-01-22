import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    TIMEOUT = int(os.getenv("TIMEOUT", 10))
    MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", 20))
    USER_AGENT = os.getenv(
        "USER_AGENT",
        "SentinelX Security Scanner"
    )
