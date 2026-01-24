import requests
import logging

logger = logging.getLogger("SentinelX")

# Static resource extensions to skip
STATIC_EXTENSIONS = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.woff', '.woff2', '.ttf', '.ico', '.webp', '.bmp', '.tiff'
}

# Request timeout configurations
DEFAULT_TIMEOUT = 3  # Reduced from 10 seconds
CRAWLER_TIMEOUT = 2  # Even shorter for crawling
TECH_DETECT_TIMEOUT = 2  # Technology detection


def should_skip_url(url):
    """Check if URL points to a static resource that should be skipped."""
    from urllib.parse import urlparse
    parsed = urlparse(url.lower())

    # Skip static file extensions
    for ext in STATIC_EXTENSIONS:
        if parsed.path.endswith(ext):
            return True

    return False


def make_request(method, url, **kwargs):
    """Make HTTP request with optimized timeout and error handling."""
    if should_skip_url(url):
        logger.debug(f"Skipping static resource: {url}")
        return None

    # Set default timeout if not specified
    if 'timeout' not in kwargs:
        kwargs['timeout'] = DEFAULT_TIMEOUT

    try:
        response = requests.request(method, url, **kwargs)
        return response
    except requests.RequestException as e:
        logger.debug(f"Request failed for {url}: {e}")
        return None


def get_with_timeout(url, timeout=None):
    """GET request with optimized timeout."""
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    return make_request('GET', url, timeout=timeout)


def post_with_timeout(url, data=None, timeout=None):
    """POST request with optimized timeout."""
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    return make_request('POST', url, data=data, timeout=timeout)
