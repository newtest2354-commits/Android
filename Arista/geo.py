import requests
import time
from cache import load_geo_cache, save_geo_cache

API_TIMEOUT = 12
MAX_RETRIES = 3
RETRY_DELAY = 1


def clean_country(country):
    if not country:
        return "Unknown"
    
    country_map = {
        "United States": "USA",
        "United Kingdom": "UK",
        "The Netherlands": "Netherlands",
        "United Arab Emirates": "UAE",
        "Russian Federation": "Russia",
        "Republic of Korea": "South Korea",
        "Democratic Republic of the Congo": "Congo"
    }
    
    return country_map.get(country, country)


def clean_provider(provider):
    if not provider:
        return "Unknown"
    
    provider = str(provider)
    
    replacements = {
        " Group PLC": "",
        " PLC": "",
        ", Inc.": "",
        ", Inc": "",
        " Inc.": "",
        " Inc": "",
        " Ltd.": "",
        " Ltd": "",
        " Corporation": " Corp.",
        " Telecommunications": " Telecom",
        " Communications": " Comm.",
        " Internet": " Net",
        " Services": " Svc.",
        " Technology": " Tech",
        " Limited": " Ltd.",
        " Company": " Co.",
        " Messenger": " Msg.",
        " Telegram": " TG"
    }
    
    for old, new in replacements.items():
        provider = provider.replace(old, new)
    
    provider = " ".join(provider.split())
    
    if len(provider) > 30:
        words = provider.split()
        if len(words) > 3:
            provider = " ".join(words[:3]) + "..."
    
    return provider.strip()


def geo_lookup(ip):
    cache = load_geo_cache()

    if ip in cache:
        return cache[ip]

    best_result = None

    sources = [
        {
            "name": "ip-api.com",
            "url": f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,mobile,proxy,hosting",
            "parser": lambda d: {
                "country": clean_country(d.get("country")),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("isp") or d.get("org")),
                "asn": d.get("as")
            } if d.get("status") == "success" else None
        },
        {
            "name": "ipwho.is",
            "url": f"https://ipwho.is/{ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("country")),
                "region": d.get("region"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("connection", {}).get("isp")),
                "asn": d.get("connection", {}).get("asn")
            } if d.get("success") is not False else None
        },
        {
            "name": "ipapi.co",
            "url": f"https://ipapi.co/{ip}/json/",
            "parser": lambda d: {
                "country": clean_country(d.get("country_name")),
                "region": d.get("region"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("org")),
                "asn": d.get("asn")
            } if d.get("country_name") else None
        },
        {
            "name": "freeipapi.com",
            "url": f"https://freeipapi.com/api/json/{ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("countryName")),
                "region": d.get("regionName"),
                "city": d.get("cityName"),
                "provider": "Unknown",
                "asn": None
            } if d.get("countryName") else None
        },
        {
            "name": "ipinfo.io",
            "url": f"https://ipinfo.io/{ip}/json",
            "parser": lambda d: {
                "country": clean_country(d.get("country")),
                "region": d.get("region"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("org")),
                "asn": d.get("asn")
            } if d.get("country") else None
        },
        {
            "name": "ipgeolocation.io",
            "url": f"https://api.ipgeolocation.io/ipgeo?ip={ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("country_name")),
                "region": d.get("state_prov"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("isp")),
                "asn": d.get("asn")
            } if d.get("country_name") else None
        },
        {
            "name": "jsonip.com",
            "url": f"https://jsonip.com/{ip}?callback=",
            "parser": lambda d: {
                "country": clean_country(d.get("country")),
                "region": d.get("region"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("org")),
                "asn": d.get("asn")
            } if d.get("country") else None
        },
        {
            "name": "ipvigilante.com",
            "url": f"https://ipvigilante.com/json/{ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("data", {}).get("country_name")),
                "region": d.get("data", {}).get("region"),
                "city": d.get("data", {}).get("city"),
                "provider": clean_provider(d.get("data", {}).get("isp")),
                "asn": d.get("data", {}).get("asn")
            } if d.get("status") == "success" else None
        },
        {
            "name": "ipapi.com",
            "url": f"https://ipapi.com/ip_api.php?ip={ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("country_name")),
                "region": d.get("region_name"),
                "city": d.get("city"),
                "provider": clean_provider(d.get("isp")),
                "asn": d.get("asn")
            } if d.get("country_name") else None
        },
        {
            "name": "ip2location.io",
            "url": f"https://api.ip2location.io/?ip={ip}",
            "parser": lambda d: {
                "country": clean_country(d.get("country_name")),
                "region": d.get("region_name"),
                "city": d.get("city_name"),
                "provider": clean_provider(d.get("isp")),
                "asn": d.get("asn")
            } if d.get("country_name") else None
        }
    ]

    for source in sources:
        for attempt in range(MAX_RETRIES):
            try:
                r = requests.get(
                    source["url"],
                    timeout=API_TIMEOUT,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    }
                )
                if r.status_code == 200:
                    data = r.json()
                    parsed = source["parser"](data)

                    if not parsed:
                        continue

                    if not best_result:
                        best_result = parsed

                    city = parsed.get("city")
                    region = parsed.get("region")

                    if city and city not in ("Unknown", ""):
                        best_result = parsed
                        print(f"GEO: {ip} -> {source['name']} -> City: {city}")
                        break

                    if region and region not in ("Unknown", ""):
                        best_result = parsed
                        print(f"GEO: {ip} -> {source['name']} -> Region: {region}")

            except:
                time.sleep(RETRY_DELAY)
                continue

        if best_result and best_result.get("city") and best_result.get("city") not in ("Unknown", ""):
            break

    if best_result is None:
        best_result = {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "provider": "Unknown",
            "asn": "Unknown"
        }

    cache[ip] = best_result
    save_geo_cache(cache)

    return best_result
