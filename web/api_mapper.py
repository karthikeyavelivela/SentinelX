from urllib.parse import urljoin, urlparse


def map_endpoints(host, crawl_eps, js_eps):
    """
    Produces a normalized endpoint object used by all phases.
    """

    all_eps = set()

    for e in crawl_eps:
        if e:
            all_eps.add(e)

    for e in js_eps:
        if e:
            all_eps.add(e)

    mapped = []

    for ep in all_eps:
        ep = normalize_endpoint(ep)

        full_url = urljoin(host.rstrip("/") + "/", ep.lstrip("/"))

        mapped.append({
            "host": host.rstrip("/"),
            "path": ep,
            "url": full_url,
            "method": "GET",
            "parameters": extract_params(ep),
            "source": "crawler/js"
        })

    return mapped


def normalize_endpoint(ep):
    ep = ep.strip()

    if ep.startswith("//"):
        ep = ep[1:]

    if not ep.startswith("/"):
        ep = "/" + ep

    # remove fragments
    ep = ep.split("#")[0]

    return ep


def extract_params(endpoint):
    params = []

    if "?" in endpoint:
        query = endpoint.split("?", 1)[1]
        for p in query.split("&"):
            key = p.split("=")[0]
            if key:
                params.append(key)

    if "{id}" in endpoint or "/:" in endpoint:
        params.append("id")

    return list(set(params))
