import logging
import os

def setup_logger():
    os.makedirs("output", exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler("output/sentinelx.log"),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger("SentinelX")
