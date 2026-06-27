import os
import json

RESULT_FILE = "output/results.txt"
BEST_FILE = "output/best_ips.txt"
DOMAINS_RAW_FILE = "output/domains_raw.txt"
DOMAINS_IPS_FILE = "output/domains_ips.txt"
TLS_FILE = "output/tls_live.txt"
GEO_FILE = "output/geo_cache.json"

KNOWN_CDN_BONUS = 2
H2_BONUS = 2
RELIABILITY_BONUS = 3

FAST_TTFB_BONUS = 4
MID_TTFB_BONUS = 2
SLOW_TTFB_BONUS = 1

STABLE_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
STABLE_PORT_BONUS = 1

MAX_BEST_IPS_SIZE_MB = 50


def parse_line(line):
    line = line.strip()

    if not line:
        return None

    parts = line.split("|")

    if len(parts) < 10:
        return None

    try:
        port = int(parts[1])
    except:
        return None

    try:
        status = int(parts[2])
    except:
        status = 0

    try:
        ttfb = int(parts[3])
    except:
        ttfb = 9999

    try:
        reliability = float(parts[5])
    except:
        reliability = 0

    return {
        "ip": parts[0],
        "port": port,
        "status": status,
        "ttfb": ttfb,
        "proto": parts[4],
        "reliability": reliability,
        "ws": parts[6],
        "cdn": parts[7],
        "country": parts[8],
        "provider": parts[9]
    }


def load_results():
    data = []
    seen = set()

    try:
        with open(RESULT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                item = parse_line(line)
                if not item:
                    continue

                key = f'{item["ip"]}:{item["port"]}'
                if key in seen:
                    continue

                seen.add(key)
                data.append(item)
    except:
        pass

    return data


def load_domains_ips():
    ips = set()
    if not os.path.exists(DOMAINS_IPS_FILE):
        return ips
    try:
        with open(DOMAINS_IPS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    ips.add(line)
    except:
        pass
    return ips


def load_tls_sni():
    sni_map = {}

    if not os.path.exists(TLS_FILE):
        return sni_map

    try:
        with open(TLS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(":")
                if len(parts) >= 5:
                    ip = parts[0]
                    port = parts[1]
                    sni = parts[4]
                    key = f"{ip}:{port}"
                    sni_map[key] = sni
    except:
        pass

    return sni_map


def load_tcp_latency():
    tcp_map = {}

    if not os.path.exists(TLS_FILE):
        return tcp_map

    try:
        with open(TLS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(":")
                if len(parts) >= 3:
                    ip = parts[0]
                    port = parts[1]
                    latency = parts[2]
                    key = f"{ip}:{port}"
                    if latency.isdigit():
                        tcp_map[key] = int(latency)
                    else:
                        tcp_map[key] = 9999
    except:
        pass

    return tcp_map


def load_geo_city():
    city_map = {}

    if not os.path.exists(GEO_FILE):
        return city_map

    try:
        with open(GEO_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for ip, info in data.items():
                if isinstance(info, dict):
                    city = info.get("city", "")
                    if city and city != "Unknown":
                        city_map[ip] = city
    except:
        pass

    return city_map


def load_geo_asn():
    asn_map = {}

    if not os.path.exists(GEO_FILE):
        return asn_map

    try:
        with open(GEO_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for ip, info in data.items():
                if isinstance(info, dict):
                    asn = info.get("asn", "")
                    if asn and asn != "Unknown":
                        asn_map[ip] = asn
    except:
        pass

    return asn_map


def load_domains_raw():
    domains = set()

    if not os.path.exists(DOMAINS_RAW_FILE):
        return domains

    try:
        with open(DOMAINS_RAW_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    domains.add(line.lower())
    except:
        pass

    return domains


def get_port_type(port):
    if port in {443, 8443, 2053, 2083, 2087, 2096}:
        return "HTTPS"
    elif port in {80, 8080}:
        return "HTTP"
    else:
        return "UNKNOWN"


def get_file_size_mb(lines):
    total = 0
    for line in lines:
        total += len(line.encode('utf-8'))
    return total / (1024 * 1024)


def extract_score_from_line(line):
    try:
        score_match = line.split('[SCORE=')[1].split(']')[0]
        return int(score_match)
    except:
        return 0


def extract_ttfb_from_line(line):
    try:
        ttfb_match = line.split('[TTFB=')[1].split('ms')[0]
        return int(ttfb_match)
    except:
        return 9999


def extract_tcp_from_line(line):
    try:
        tcp_part = line.split('[TCP=')[1].split(']')[0]
        if tcp_part == "DOMAIN" or tcp_part == "timeout":
            return 9999
        return int(tcp_part.replace('ms', '')) if tcp_part.replace('ms', '').isdigit() else 9999
    except:
        return 9999


def parse_line_to_dict(line):
    try:
        ip = line.split('[IP: ')[1].split(']')[0]
        port = int(line.split('[PORT: ')[1].split(']')[0])
        score = extract_score_from_line(line)
        tcp = extract_tcp_from_line(line)
        ttfb = extract_ttfb_from_line(line)
        return {"ip": ip, "port": port, "score": score, "tcp": tcp, "ttfb": ttfb, "line": line}
    except:
        return None


def rank_results():
    data = load_results()
    domains_set = load_domains_raw()
    domains_ips = load_domains_ips()
    sni_map = load_tls_sni()
    city_map = load_geo_city()
    asn_map = load_geo_asn()
    tcp_map = load_tcp_latency()

    ranked = []

    for item in data:
        item["score"] = score(item)
        item["tcp"] = tcp_map.get(f"{item['ip']}:{item['port']}", 9999)
        ranked.append(item)

    existing_ips = {item['ip'] for item in ranked}

    for ip in domains_ips:
        if ip not in existing_ips:
            ranked.append({
                'ip': ip,
                'port': 443,
                'score': 5,
                'tcp': tcp_map.get(f"{ip}:443", 9999),
                'ttfb': 500,
                'proto': 'unknown',
                'reliability': 0.5,
                'cdn': 'unknown',
                'country': 'Unknown',
                'provider': 'Unknown'
            })

    ranked.sort(
        key=lambda x: (
            x.get("tcp", 9999),
            -x["score"],
            x.get("ttfb", 9999),
            x.get("port", 65535)
        )
    )

    os.makedirs("output", exist_ok=True)

    new_lines = []
    for item in ranked:
        ip = item["ip"]
        port = item["port"]
        key = f"{ip}:{port}"

        country = item.get("country", "-")
        provider = item.get("provider", "-")

        sni = sni_map.get(key, "-")
        tcp_latency = item.get("tcp", "N/A")

        if tcp_latency == 9999:
            tcp_display = "timeout"
        else:
            tcp_display = f"{tcp_latency}ms"

        city = city_map.get(ip, "-")
        asn = asn_map.get(ip, "")

        port_type = get_port_type(port)

        domain = "-"
        for d in sorted(domains_set):
            if d in sni or sni in d:
                domain = d
                break

        parts = [
            f'[IP: {ip}]',
            f'[PORT: {port}]',
            f'[SCORE={item["score"]}]',
            f'[TCP={tcp_display}]',
            f'[TTFB={item.get("ttfb", "-")}ms]',
            f'[PROTO={item.get("proto", "-")}]',
            f'[REL={item.get("reliability", "-")}]',
            f'[CDN={item.get("cdn", "-")}]',
            f'[TYPE={port_type}]'
        ]

        if domain and domain != "-":
            parts.append(f'[DOMAIN={domain}]')

        if sni and sni != "-":
            parts.append(f'[SNI={sni}]')

        if city and city != "-" and city != "Unknown":
            parts.append(f'[City={city}]')

        if country and country != "-" and country != "Unknown":
            parts.append(f'[Country={country}]')

        if provider and provider != "-" and provider != "Unknown":
            parts.append(f'[Provider={provider}]')

        if asn and asn != "Unknown":
            parts.append(f'[ASN={asn}]')

        line = " ".join(parts) + "\n"
        new_lines.append(line)

    old_lines = []
    old_ips = {}
    if os.path.exists(BEST_FILE):
        try:
            with open(BEST_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = parse_line_to_dict(line)
                    if parsed:
                        old_lines.append(line)
                        key = f"{parsed['ip']}:{parsed['port']}"
                        old_ips[key] = parsed
        except:
            pass

    combined_dict = {}

    for line in new_lines:
        parsed = parse_line_to_dict(line)
        if parsed:
            key = f"{parsed['ip']}:{parsed['port']}"
            combined_dict[key] = parsed

    for key, parsed in old_ips.items():
        if key not in combined_dict:
            combined_dict[key] = parsed

    combined = sorted(
        combined_dict.values(),
        key=lambda x: (x["tcp"], -x["score"], x["ttfb"], x["port"])
    )

    combined_lines = [item["line"] for item in combined]

    unique_ips = set()
    unique_lines = []
    for line in combined_lines:
        if '[IP: ' in line:
            ip_match = line.split('[IP: ')[1].split(']')[0]
            if ip_match not in unique_ips:
                unique_ips.add(ip_match)
                unique_lines.append(line)
        else:
            unique_lines.append(line)

    combined_lines = unique_lines

    current_size_mb = get_file_size_mb(combined_lines)

    if current_size_mb > MAX_BEST_IPS_SIZE_MB:
        print(f"FILE SIZE {current_size_mb:.2f}MB EXCEEDED {MAX_BEST_IPS_SIZE_MB}MB! REMOVING WORST TCP ENTRIES...")
        while current_size_mb > MAX_BEST_IPS_SIZE_MB and len(combined_lines) > 100:
            removed = combined_lines.pop()
            current_size_mb = get_file_size_mb(combined_lines)
            print(f"REMOVED HIGH TCP ENTRY... NEW SIZE: {current_size_mb:.2f}MB")

    with open(BEST_FILE, "w", encoding="utf-8") as f:
        f.writelines(combined_lines)

    print(f"BEST_IPS_SIZE: {current_size_mb:.2f}MB")
    print(f"BEST_IPS_LINES: {len(combined_lines)}")
    print(f"RANKED={len(ranked)} DOMAINS={len(domains_set)} DOMAIN_IPS={len(domains_ips)}")


def ttfb_score(ttfb):
    if ttfb <= 150:
        return FAST_TTFB_BONUS
    elif ttfb <= 300:
        return MID_TTFB_BONUS
    elif ttfb <= 500:
        return SLOW_TTFB_BONUS
    else:
        return 0


def cdn_score(cdn):
    if not cdn:
        return 0
    cdn = str(cdn).strip().lower()
    if cdn == "unknown":
        return 0
    if cdn in ["cloudflare", "fastly", "akamai", "bunny", "gcore", "vercel", "cloudfront", "facebook", "google", "amazon", "microsoft", "twitter", "instagram", "youtube", "telegram"]:
        return KNOWN_CDN_BONUS
    return 0


def port_score(port):
    if port in STABLE_PORTS:
        return STABLE_PORT_BONUS
    return 0


def score(item):
    total = 0

    total += ttfb_score(item.get("ttfb", 9999))
    total += cdn_score(item.get("cdn", ""))
    total += port_score(item.get("port", 0))

    proto = item.get("proto", "").lower()
    if "h2" in proto:
        total += H2_BONUS

    reliability = item.get("reliability", 0)
    if reliability >= 0.9:
        total += RELIABILITY_BONUS

    return total


if __name__ == "__main__":
    rank_results()
