import os
import json
import re

RESULT_FILE = "output/results.txt"
BEST_FILE = "output/best_ips.txt"
DOMAINS_RAW_FILE = "output/domains_raw.txt"
DOMAINS_IPS_FILE = "output/domains_ips.txt"
TLS_FILE = "output/tls_live.txt"
GEO_FILE = "output/geo_cache.json"

KNOWN_CDN_BONUS = 2
STABLE_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
MAX_BEST_IPS_SIZE_MB = 50

def parse_line(line):
    line = line.strip()
    if not line:
        return None
    parts = line.split("|")
    if len(parts) < 10:
        return None
    try:
        return {
            "ip": parts[0],
            "port": int(parts[1]),
            "status": int(parts[2]) if parts[2].isdigit() else 0,
            "ttfb": int(parts[3]) if parts[3].isdigit() else 9999,
            "proto": parts[4],
            "reliability": float(parts[5]) if parts[5].replace('.', '').isdigit() else 0,
            "ws": parts[6],
            "cdn": parts[7],
            "country": parts[8],
            "provider": parts[9]
        }
    except:
        return None

def load_results():
    data = []
    seen = set()
    try:
        with open(RESULT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                item = parse_line(line)
                if item:
                    key = f'{item["ip"]}:{item["port"]}'
                    if key not in seen:
                        seen.add(key)
                        data.append(item)
    except:
        pass
    return data

def load_domains_ips():
    if not os.path.exists(DOMAINS_IPS_FILE):
        return set()
    try:
        with open(DOMAINS_IPS_FILE, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except:
        return set()

def load_tls_sni():
    sni_map = {}
    if not os.path.exists(TLS_FILE):
        return sni_map
    try:
        with open(TLS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 5:
                    sni_map[f"{parts[0]}:{parts[1]}"] = parts[4]
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
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    match = re.search(r'(\d+)', parts[2])
                    tcp_map[f"{parts[0]}:{parts[1]}"] = int(match.group(1)) if match else 9999
    except:
        pass
    return tcp_map

def load_geo_data():
    city_map = {}
    asn_map = {}
    if not os.path.exists(GEO_FILE):
        return city_map, asn_map
    try:
        with open(GEO_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for ip, info in data.items():
                if isinstance(info, dict):
                    city = info.get("city", "")
                    if city and city != "Unknown":
                        city_map[ip] = city
                    asn = info.get("asn", "")
                    if asn and asn != "Unknown":
                        asn_map[ip] = asn
    except:
        pass
    return city_map, asn_map

def load_domains_raw():
    if not os.path.exists(DOMAINS_RAW_FILE):
        return set()
    try:
        with open(DOMAINS_RAW_FILE, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except:
        return set()

def get_port_type(port):
    if port in STABLE_PORTS:
        return "HTTPS"
    elif port in {80, 8080}:
        return "HTTP"
    return "UNKNOWN"

def extract_score_from_line(line):
    try:
        return int(line.split('[SCORE=')[1].split(']')[0])
    except:
        return 0

def extract_ttfb_from_line(line):
    try:
        return int(line.split('[TTFB=')[1].split('ms')[0])
    except:
        return 9999

def extract_tcp_from_line(line):
    try:
        tcp_part = line.split('[TCP=')[1].split(']')[0]
        if tcp_part in ("DOMAIN", "timeout"):
            return 9999
        match = re.search(r'(\d+)', tcp_part)
        return int(match.group(1)) if match else 9999
    except:
        return 9999

def parse_line_to_dict(line):
    try:
        ip = line.split('[IP: ')[1].split(']')[0]
        port = int(line.split('[PORT: ')[1].split(']')[0])
        return {
            "ip": ip,
            "port": port,
            "score": extract_score_from_line(line),
            "tcp": extract_tcp_from_line(line),
            "ttfb": extract_ttfb_from_line(line),
            "line": line.strip()
        }
    except:
        return None

def find_domain_for_ip(ip, domains_set, sni_map, port):
    key = f"{ip}:{port}"
    sni = sni_map.get(key, "")
    if sni:
        sni_lower = sni.lower()
        for d in domains_set:
            if d in sni_lower:
                return d
    for d in domains_set:
        if d in ip:
            return d
    return "-"

def score_item(item):
    total = 0
    ttfb = item.get("ttfb", 9999)
    if ttfb <= 50:
        total += 8
    elif ttfb <= 100:
        total += 7
    elif ttfb <= 150:
        total += 6
    elif ttfb <= 200:
        total += 5
    elif ttfb <= 300:
        total += 4
    elif ttfb <= 500:
        total += 2

    reliability = item.get("reliability", 0)
    if reliability >= 0.99:
        total += 8
    elif reliability >= 0.95:
        total += 7
    elif reliability >= 0.90:
        total += 6
    elif reliability >= 0.80:
        total += 4
    elif reliability >= 0.70:
        total += 2

    proto = str(item.get("proto", "")).lower()
    if "h2" in proto:
        total += 3
    elif "http/1.1" in proto:
        total += 1

    cdn = str(item.get("cdn", "")).strip().lower()
    if cdn and cdn != "unknown" and cdn in ["cloudflare", "fastly", "akamai", "bunny", "gcore", "vercel", "cloudfront", "facebook", "google", "amazon", "microsoft", "twitter", "instagram", "youtube", "telegram"]:
        total += KNOWN_CDN_BONUS

    if item.get("port", 0) in STABLE_PORTS:
        total += 1

    return total

def rank_results():
    data = load_results()
    if not data:
        print("NO DATA TO RANK")
        return

    domains_set = load_domains_raw()
    domains_ips = load_domains_ips()
    sni_map = load_tls_sni()
    city_map, asn_map = load_geo_data()
    tcp_map = load_tcp_latency()

    ranked = []
    for item in data:
        item["score"] = score_item(item)
        item["tcp"] = tcp_map.get(f"{item['ip']}:{item['port']}", 9999)
        ranked.append(item)

    existing_ips = {item['ip'] for item in ranked}
    for ip in domains_ips:
        if ip not in existing_ips:
            found = False
            for item in data:
                if item['ip'] == ip:
                    temp_item = item.copy()
                    temp_item["score"] = score_item(temp_item)
                    temp_item["tcp"] = tcp_map.get(f"{ip}:{temp_item['port']}", 9999)
                    ranked.append(temp_item)
                    found = True
                    break
            if not found:
                ranked.append({
                    'ip': ip,
                    'port': 443,
                    'ttfb': 9999,
                    'proto': 'unknown',
                    'reliability': 0,
                    'cdn': 'unknown',
                    'country': 'Unknown',
                    'provider': 'Unknown',
                    'score': 0,
                    'tcp': tcp_map.get(f"{ip}:443", 9999)
                })

    ranked.sort(key=lambda x: (-x["score"], x.get("tcp", 9999), x.get("ttfb", 9999), -x.get("reliability", 0), x.get("port", 65535)))

    os.makedirs("output", exist_ok=True)

    new_lines = []
    seen_ips = set()
    for item in ranked:
        ip, port = item["ip"], item["port"]

        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        
        key = f"{ip}:{port}"
        sni = sni_map.get(key, "-")
        tcp_latency = item.get("tcp", "N/A")
        tcp_display = "timeout" if tcp_latency == 9999 else f"{tcp_latency}ms"
        city = city_map.get(ip, "-")
        asn = asn_map.get(ip, "")
        port_type = get_port_type(port)
        domain = find_domain_for_ip(ip, domains_set, sni_map, port)

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
        if item.get("country") and item["country"] != "-" and item["country"] != "Unknown":
            parts.append(f'[Country={item["country"]}]')
        if item.get("provider") and item["provider"] != "-" and item["provider"] != "Unknown":
            parts.append(f'[Provider={item["provider"]}]')
        if asn and asn != "Unknown":
            parts.append(f'[ASN={asn}]')

        new_lines.append(" ".join(parts))

    old_ips = {}
    if os.path.exists(BEST_FILE):
        try:
            with open(BEST_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line: 
                        continue
                    if parsed := parse_line_to_dict(line):
                        old_ips[parsed['ip']] = parsed
        except:
            pass

    combined_dict = {}
    for line in new_lines:
        if parsed := parse_line_to_dict(line):
            combined_dict[parsed['ip']] = parsed

    for ip, parsed in old_ips.items():
        if ip not in combined_dict:
            combined_dict[ip] = parsed

    combined = sorted(
        combined_dict.values(),
        key=lambda x: (-x["score"], x["tcp"], x["ttfb"])
    )

    combined_lines = [item["line"] for item in combined]

    current_size_mb = sum(len(line.encode('utf-8')) for line in combined_lines) / (1024 * 1024)

    if current_size_mb > MAX_BEST_IPS_SIZE_MB:
        print(f"FILE SIZE {current_size_mb:.2f}MB EXCEEDED {MAX_BEST_IPS_SIZE_MB}MB! REMOVING LOWEST SCORE ENTRIES...")
        while current_size_mb > MAX_BEST_IPS_SIZE_MB and len(combined_lines) > 100:
            combined_lines.pop()
            current_size_mb = sum(len(line.encode('utf-8')) for line in combined_lines) / (1024 * 1024)
            print(f"REMOVED LOWEST SCORE ENTRY... NEW SIZE: {current_size_mb:.2f}MB")

    with open(BEST_FILE, "w", encoding="utf-8") as f:
        if combined_lines:
            f.write("\n".join(combined_lines) + "\n")
        else:
            f.write("")

    print(f"BEST_IPS_SIZE: {current_size_mb:.2f}MB")
    print(f"BEST_IPS_LINES: {len(combined_lines)}")
    print(f"RANKED={len(ranked)} DOMAINS={len(domains_set)} DOMAIN_IPS={len(domains_ips)}")

if __name__ == "__main__":
    rank_results()
