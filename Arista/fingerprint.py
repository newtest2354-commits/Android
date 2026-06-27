import requests

requests.packages.urllib3.disable_warnings()

CDN_HEADERS = {
    "cloudflare": [
        "cf-ray",
        "cf-cache-status",
        "cf-worker",
        "cf-request-id",
        "cf-pop"
    ],
    "fastly": [
        "x-served-by",
        "fastly-debug",
        "x-cache",
        "x-cache-hits",
        "x-timer"
    ],
    "akamai": [
        "akamai",
        "x-akamai",
        "x-akamai-transformed",
        "x-akamai-request-id"
    ],
    "azure": [
        "x-azure-ref",
        "x-ms-request-id",
        "x-ms-version"
    ],
    "bunny": [
        "bunnycdn",
        "x-bunny-cache",
        "x-bunny-cache-status"
    ],
    "gcore": [
        "gcdn",
        "x-gcdn",
        "x-gcdn-cache"
    ],
    "vercel": [
        "x-vercel-id",
        "x-vercel-cache",
        "x-vercel-deployment-id"
    ],
    "cloudfront": [
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "x-cache"
    ],
    "incapsula": [
        "x-cdn",
        "x-iinfo",
        "x-cdn-info"
    ],
    "sucuri": [
        "x-sucuri-id",
        "x-sucuri-cache"
    ],
    "stackpath": [
        "x-stackpath",
        "x-stackpath-cache"
    ],
    "leaseweb": [
        "x-lsw",
        "x-lsw-cache"
    ],
    "cdnsun": [
        "x-cdnsun",
        "x-cdnsun-cache"
    ],
    "belugacdn": [
        "x-belugacdn",
        "x-belugacdn-cache"
    ],
    "quiccloud": [
        "x-quic",
        "x-quic-cache"
    ],
    "cachefly": [
        "x-cachefly",
        "x-cachefly-cache"
    ],
    "edgemesh": [
        "x-edgemesh",
        "x-edge"
    ],
    "hwcdn": [
        "x-hwcdn",
        "x-hwcdn-cache"
    ],
    "highwinds": [
        "x-highwinds",
        "x-hw"
    ],
    "cdn77": [
        "x-cdn77",
        "x-cdn77-cache"
    ],
    "facebook": [
        "x-fb-",
        "fb-",
        "x-facebook"
    ],
    "google": [
        "x-guploader",
        "x-gstatic",
        "alt-svc"
    ],
    "amazon": [
        "x-amz-",
        "server: AmazonS3"
    ],
    "microsoft": [
        "x-ms-",
        "azure"
    ],
    "twitter": [
        "x-twitter",
        "twimg"
    ],
    "instagram": [
        "x-instagram",
        "cdninstagram"
    ],
    "youtube": [
        "x-youtube",
        "ytimg"
    ]
}

TLS_PORTS = {
    443,
    8443,
    2053,
    2083,
    2087,
    2096
}


def safe_lower(v):
    try:
        return str(v).lower()
    except:
        return ""


def normalize_headers(headers):
    if not headers:
        return {}
    out = {}
    try:
        for k, v in headers.items():
            out[safe_lower(k)] = safe_lower(v)
    except:
        return {}
    return out


def detect_cdn_from_headers(headers):
    headers = normalize_headers(headers)
    for cdn, signs in CDN_HEADERS.items():
        for sign in signs:
            sign = safe_lower(sign)
            if sign in headers:
                return cdn
            if any(sign in v for v in headers.values()):
                return cdn

    server = headers.get("server", "")
    if "cloudflare" in server:
        return "cloudflare"
    if "fastly" in server:
        return "fastly"
    if "akamai" in server:
        return "akamai"
    if "bunny" in server:
        return "bunny"
    if "gcore" in server:
        return "gcore"
    if "vercel" in server:
        return "vercel"
    if "cloudfront" in server:
        return "cloudfront"
    if "incapsula" in server:
        return "incapsula"
    if "sucuri" in server:
        return "sucuri"
    if "stackpath" in server:
        return "stackpath"
    if "leaseweb" in server:
        return "leaseweb"
    if "cdnsun" in server:
        return "cdnsun"
    if "belugacdn" in server:
        return "belugacdn"
    if "quiccloud" in server:
        return "quiccloud"
    if "cachefly" in server:
        return "cachefly"
    if "edgemesh" in server:
        return "edgemesh"
    if "hwcdn" in server or "highwinds" in server:
        return "highwinds"
    if "cdn77" in server:
        return "cdn77"
    if "facebook" in server:
        return "facebook"
    if "google" in server:
        return "google"
    if "amazon" in server:
        return "amazon"
    if "microsoft" in server:
        return "microsoft"
    if "twitter" in server:
        return "twitter"
    if "instagram" in server:
        return "instagram"
    if "youtube" in server:
        return "youtube"

    return "unknown"


def detect_cdn_from_tls(issuer):
    issuer_lower = safe_lower(issuer)

    cdn_identifiers = {
        "cloudflare": ["cloudflare"],
        "fastly": ["fastly"],
        "akamai": ["akamai"],
        "azure": ["azure"],
        "bunny": ["bunny"],
        "gcore": ["gcore"],
        "vercel": ["vercel"],
        "cloudfront": ["cloudfront"],
        "incapsula": ["incapsula"],
        "sucuri": ["sucuri"],
        "stackpath": ["stackpath"],
        "leaseweb": ["leaseweb"],
        "cdnsun": ["cdnsun"],
        "belugacdn": ["belugacdn"],
        "quiccloud": ["quiccloud"],
        "cachefly": ["cachefly"],
        "edgemesh": ["edgemesh"],
        "highwinds": ["highwinds", "hwcdn"],
        "cdn77": ["cdn77"],
        "facebook": ["facebook", "fbcdn"],
        "google": ["google", "gstatic"],
        "amazon": ["amazon", "aws"],
        "microsoft": ["microsoft"],
        "twitter": ["twitter", "twimg"],
        "instagram": ["instagram"],
        "youtube": ["youtube", "ytimg"],
        "telegram": ["telegram", "tdesktop"]
    }

    for cdn, identifiers in cdn_identifiers.items():
        for identifier in identifiers:
            if identifier in issuer_lower:
                return cdn

    return "unknown"


def detect_cdn_from_asn(provider):
    provider_lower = safe_lower(provider)

    cdn_providers = {
        "cloudflare": ["cloudflare"],
        "fastly": ["fastly"],
        "akamai": ["akamai"],
        "azure": ["azure", "microsoft"],
        "bunny": ["bunny"],
        "gcore": ["gcore"],
        "vercel": ["vercel"],
        "cloudfront": ["cloudfront"],
        "incapsula": ["incapsula", "imperva"],
        "sucuri": ["sucuri"],
        "stackpath": ["stackpath"],
        "leaseweb": ["leaseweb"],
        "cdnsun": ["cdnsun"],
        "belugacdn": ["beluga"],
        "quiccloud": ["quic"],
        "cachefly": ["cachefly"],
        "edgemesh": ["edgemesh"],
        "highwinds": ["highwinds", "stack"],
        "cdn77": ["cdn77"],
        "facebook": ["facebook"],
        "google": ["google"],
        "amazon": ["amazon", "aws"],
        "twitter": ["twitter"],
        "instagram": ["instagram"],
        "youtube": ["youtube"],
        "telegram": ["telegram"]
    }

    for cdn, providers in cdn_providers.items():
        for provider_name in providers:
            if provider_name in provider_lower:
                return cdn

    return "unknown"


def detect_cdn(ip=None, port=None, headers=None, issuer=None, sni=None, alpn=None, provider=None):
    if headers is not None:
        cdn = detect_cdn_from_headers(headers)
        if cdn != "unknown":
            return cdn

    if provider is not None:
        cdn = detect_cdn_from_asn(provider)
        if cdn != "unknown":
            return cdn

    if issuer is not None:
        cdn = detect_cdn_from_tls(issuer)
        if cdn != "unknown":
            return cdn

    if ip is not None and port is not None:
        scheme = "https" if port in TLS_PORTS else "http"
        try:
            r = requests.get(
                f"{scheme}://{ip}",
                timeout=4,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            cdn = detect_cdn_from_headers(r.headers)
            if cdn != "unknown":
                return cdn
        except:
            pass

    return "unknown"
