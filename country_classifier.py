import os
import re
import json
import socket
import base64
import requests
import ipaddress
from urllib.parse import urlparse, unquote
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

class CountryClassifier:
    def __init__(self):
        self.categories = ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'other']
        self.geo_cache = {}
        self.output_dir = 'configs_by_country'
        os.makedirs(self.output_dir, exist_ok=True)

    def b64_decode(self, s):
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            return base64.b64decode(s + pad).decode(errors='ignore')
        except:
            return None

    def get_country_by_ip(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        try:
            resp = requests.get(f"https://ipwhois.app/json/{ip}", timeout=5)
            if resp.status_code == 200:
                code = resp.json().get("country_code", "unknown").lower()
                self.geo_cache[ip] = code
                return code
        except:
            pass
        self.geo_cache[ip] = "unknown"
        return "unknown"

    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except:
            return False

    def extract_host_port(self, config_str):
        try:
            if config_str.startswith('vmess://'):
                decoded = self.b64_decode(config_str[8:])
                if decoded:
                    cfg = json.loads(decoded)
                    host = cfg.get('add', '')
                    port = str(cfg.get('port', ''))
                    return host, port
            elif config_str.startswith('ss://'):
                body = config_str[5:].split('#')[0]
                if '@' in body:
                    creds, hostport = body.split('@', 1)
                    if ':' in hostport:
                        host, port = hostport.rsplit(':', 1)
                        return host, port
                try:
                    decoded = self.b64_decode(body)
                    if decoded and '@' in decoded:
                        creds, hostport = decoded.split('@', 1)
                        if ':' in hostport:
                            host, port = hostport.rsplit(':', 1)
                            return host, port
                except:
                    pass
            elif config_str.startswith('ssr://'):
                raw = config_str[6:]
                decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode(errors='ignore')
                parts = decoded.split(':')
                if len(parts) >= 2:
                    return parts[0], parts[1]
            else:
                parsed = urlparse(config_str)
                if parsed.netloc:
                    netloc = parsed.netloc
                    if '@' in netloc:
                        netloc = netloc.split('@')[1]
                    if ':' in netloc:
                        host, port = netloc.rsplit(':', 1)
                        return host, port
                    return netloc, '443'
        except:
            pass
        return None, None

    def resolve_host(self, host):
        if not host or self.is_ip(host):
            return host
        try:
            return socket.gethostbyname(host)
        except:
            return host

    def read_configs(self, filepath):
        if not os.path.exists(filepath):
            return []
        configs = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        return configs

    def classify_by_country(self):
        combined_dir = 'configs.txt/combined'
        if not os.path.exists(combined_dir):
            logging.error(f"Combined directory not found: {combined_dir}")
            return

        country_configs = defaultdict(lambda: defaultdict(list))
        processed = 0
        failed = 0

        for category in self.categories:
            cat_file = os.path.join(combined_dir, f"{category}.txt")
            if not os.path.exists(cat_file):
                continue

            configs = self.read_configs(cat_file)
            for config in configs:
                host, port = self.extract_host_port(config)
                if not host:
                    failed += 1
                    continue

                ip = self.resolve_host(host)
                if not ip:
                    failed += 1
                    continue

                country = self.get_country_by_ip(ip)
                if country == 'unknown':
                    country = 'zz'

                country_configs[country][category].append(config)
                processed += 1

        logging.info(f"Classified {processed} configs, failed {failed}")

        for country, categories in country_configs.items():
            country_dir = os.path.join(self.output_dir, country)
            os.makedirs(country_dir, exist_ok=True)

            all_configs = []
            for category, configs in categories.items():
                if configs:
                    cat_file = os.path.join(country_dir, f"{category}.txt")
                    with open(cat_file, 'w', encoding='utf-8') as f:
                        f.write(f"# {country.upper()} - {category.upper()}\n")
                        f.write(f"# Count: {len(configs)}\n\n")
                        f.write("\n".join(configs))
                    all_configs.extend(configs)

            if all_configs:
                all_file = os.path.join(country_dir, "all.txt")
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(f"# {country.upper()} - ALL\n")
                    f.write(f"# Count: {len(all_configs)}\n\n")
                    f.write("\n".join(all_configs))

                light_file = os.path.join(country_dir, "light.txt")
                with open(light_file, 'w', encoding='utf-8') as f:
                    f.write(f"# {country.upper()} - LIGHT (30 configs)\n")
                    f.write(f"# Count: {min(30, len(all_configs))}\n\n")
                    f.write("\n".join(all_configs[:30]))

        self.create_summary(country_configs)

    def create_summary(self, country_configs):
        summary = {
            'timestamp': datetime.now().isoformat(),
            'countries': {}
        }

        for country, categories in country_configs.items():
            summary['countries'][country] = {
                cat: len(configs) for cat, configs in categories.items()
            }
            summary['countries'][country]['total'] = sum(len(c) for c in categories.values())

        with open(os.path.join(self.output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        logging.info(f"Created summary for {len(country_configs)} countries")

def main():
    classifier = CountryClassifier()
    classifier.classify_by_country()

if __name__ == "__main__":
    main()
