import jwt
import logging

logger = logging.getLogger("SentinelX")


def analyze_jwt(token):
    issues = []

    try:
        header = jwt.get_unverified_header(token)

        if header.get("alg") == "none":
            issues.append("JWT uses alg=none")

    except Exception:
        pass

    return issues
