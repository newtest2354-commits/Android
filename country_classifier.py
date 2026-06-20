import os
import re
import json
import socket
import base64
import requests
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, unquote
from collections import defaultdict

class CountryClassifier:
    def __init__(self):
        self.geo_cache = {}
        self.categories = ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'other']
        self.tiers = [50, 100, 150, 200, 250, 300, 400, 500, "ALL"]
        self.country_codes = set()
        self.country_configs = defaultdict(lambda: defaultdict(list))
        self.country_flags = {}
        self.output_base = "configs.txt/country"
        
    def get_country_by_ip(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        try:
            r = requests.get(f"https://ipwhois.app/json/{ip}", timeout=5)
            if r.status_code == 200:
                code = r.json().get("country_code", "unknown").lower()
                self.geo_cache[ip] = code
                return code
        except:
            pass
        self.geo_cache[ip] = "unknown"
        return "unknown"
    
    def get_country_flag(self, code):
        if code in self.country_flags:
            return self.country_flags[code]
        if not code or len(code) != 2:
            return "🏳️"
        try:
            flag = chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)
            self.country_flags[code] = flag
            return flag
        except:
            return "🏳️"
    
    def extract_ip_from_config(self, config_str):
        try:
            if config_str.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(config_str.replace('vmess://', '')).decode('utf-8')
                    vmess = json.loads(decoded)
                    return vmess.get('add', '')
                except:
                    pass
            elif config_str.startswith('ss://'):
                try:
                    raw = config_str.replace('ss://', '').split('#')[0]
                    if '@' in raw:
                        if len(raw.split('@')[0]) % 4 == 0:
                            try:
                                decoded = base64.b64decode(raw.split('@')[0]).decode('utf-8')
                                if '@' in decoded:
                                    _, hostport = decoded.split('@', 1)
                                    if ':' in hostport:
                                        return hostport.split(':', 1)[0]
                            except:
                                pass
                        if ':' in raw.split('@')[1]:
                            return raw.split('@')[1].split(':', 1)[0]
                except:
                    pass
            elif config_str.startswith('vless://') or config_str.startswith('trojan://'):
                try:
                    parsed = urlparse(config_str)
                    return parsed.hostname or ''
                except:
                    pass
            elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
                try:
                    parsed = urlparse(config_str.replace('hy2://', 'hysteria2://'))
                    return parsed.hostname or ''
                except:
                    pass
            return ''
        except:
            return ''
    
    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except:
            return False
    
    def resolve_host(self, host):
        host = host.strip()
        if not host:
            return host
        if self.is_ip(host):
            return host
        try:
            return socket.gethostbyname(host)
        except:
            return host
    
    def classify_configs(self, configs):
        country_map = defaultdict(list)
        for config in configs:
            ip = self.extract_ip_from_config(config)
            if ip:
                resolved_ip = self.resolve_host(ip)
                if self.is_ip(resolved_ip):
                    country = self.get_country_by_ip(resolved_ip)
                    if country != "unknown":
                        country_map[country].append(config)
                        self.country_codes.add(country)
        return country_map
    
    def categorize_by_protocol(self, configs):
        categorized = defaultdict(list)
        for config in configs:
            if config.startswith('vmess://'):
                categorized['vmess'].append(config)
            elif config.startswith('vless://'):
                categorized['vless'].append(config)
            elif config.startswith('trojan://'):
                categorized['trojan'].append(config)
            elif config.startswith('ss://'):
                categorized['ss'].append(config)
            elif config.startswith('hysteria2://') or config.startswith('hy2://'):
                categorized['hysteria2'].append(config)
            elif config.startswith('hysteria://'):
                categorized['hysteria'].append(config)
            elif config.startswith('tuic://'):
                categorized['tuic'].append(config)
            elif config.startswith('wireguard://'):
                categorized['wireguard'].append(config)
            else:
                categorized['other'].append(config)
        return categorized
    
    def deduplicate(self, configs):
        seen = set()
        unique = []
        for config in configs:
            if config not in seen:
                seen.add(config)
                unique.append(config)
        return unique
    
    def add_country_flag_to_tag(self, config_str, country_code):
        flag = self.get_country_flag(country_code)
        try:
            if config_str.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(config_str.replace('vmess://', '')).decode('utf-8')
                    vmess = json.loads(decoded)
                    ps = vmess.get('ps', '')
                    if not ps.startswith(flag):
                        vmess['ps'] = f"{flag} {ps}" if ps else flag
                        new_b64 = base64.b64encode(json.dumps(vmess, ensure_ascii=False).encode()).decode()
                        return f"vmess://{new_b64}"
                except:
                    pass
            elif '#' in config_str:
                base, tag = config_str.rsplit('#', 1)
                if not tag.startswith(flag):
                    return f"{base}#{flag} {tag}"
            else:
                return f"{config_str}#{flag}"
        except:
            pass
        return config_str
    
    def process_country_configs(self, country_configs):
        os.makedirs(self.output_base, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for country, configs in country_configs.items():
            if not configs:
                continue
            unique_configs = self.deduplicate(configs)
            country_dir = os.path.join(self.output_base, country)
            os.makedirs(country_dir, exist_ok=True)
            
            categorized = self.categorize_by_protocol(unique_configs)
            
            for category, cat_configs in categorized.items():
                if not cat_configs:
                    continue
                flagged_configs = [self.add_country_flag_to_tag(c, country) for c in cat_configs]
                filepath = os.path.join(country_dir, f"{category}.txt")
                content = f"# {country.upper()} - {category.upper()} Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Count: {len(flagged_configs)}\n\n"
                content += "\n".join(flagged_configs)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            all_flagged = [self.add_country_flag_to_tag(c, country) for c in unique_configs]
            all_filepath = os.path.join(country_dir, "all.txt")
            content = f"# {country.upper()} - All Configurations\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Total Count: {len(all_flagged)}\n\n"
            content += "\n".join(all_flagged)
            with open(all_filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            light_flagged = all_flagged[:30]
            light_filepath = os.path.join(country_dir, "light.txt")
            content = f"# {country.upper()} - Light Configurations (Top 30)\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Count: {len(light_flagged)}\n\n"
            content += "\n".join(light_flagged)
            with open(light_filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.generate_tiered_country_outputs(country, all_flagged, timestamp)
    
    def generate_tiered_country_outputs(self, country, all_configs, timestamp):
        country_dir = os.path.join(self.output_base, country)
        tiered_dir = os.path.join(country_dir, "tiers")
        os.makedirs(tiered_dir, exist_ok=True)
        
        for tier in self.tiers:
            if tier == "ALL":
                selected = all_configs
            else:
                selected = all_configs[:tier] if len(all_configs) >= tier else all_configs
            if not selected:
                continue
            categorized = self.categorize_by_protocol(selected)
            tier_dir = os.path.join(tiered_dir, str(tier))
            os.makedirs(tier_dir, exist_ok=True)
            
            for category, cat_configs in categorized.items():
                if not cat_configs:
                    continue
                filepath = os.path.join(tier_dir, f"{category}.txt")
                content = f"# {country.upper()} - Tier {tier} - {category.upper()}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Count: {len(cat_configs)}\n\n"
                content += "\n".join(cat_configs)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            all_tier_filepath = os.path.join(tier_dir, "all.txt")
            content = f"# {country.upper()} - Tier {tier} - All\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Count: {len(selected)}\n\n"
            content += "\n".join(selected)
            with open(all_tier_filepath, 'w', encoding='utf-8') as f:
                f.write(content)
    
    def process_all_configs(self):
        combined_dir = "configs.txt/combined"
        if not os.path.exists(combined_dir):
            print("Combined directory not found. Run combine_configs.py first.")
            return
        
        all_configs = []
        for category in self.categories:
            cat_file = os.path.join(combined_dir, f"{category}.txt")
            if os.path.exists(cat_file):
                with open(cat_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            all_configs.append(line)
        
        all_file = os.path.join(combined_dir, "all.txt")
        if os.path.exists(all_file):
            with open(all_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_configs.append(line)
        
        if not all_configs:
            print("No configs found to classify.")
            return
        
        all_configs = self.deduplicate(all_configs)
        print(f"Total configs to classify: {len(all_configs)}")
        
        country_map = self.classify_configs(all_configs)
        
        if not country_map:
            print("No configs could be classified by country.")
            return
        
        print(f"Classified {sum(len(c) for c in country_map.values())} configs into {len(country_map)} countries")
        
        self.process_country_configs(country_map)
        
        print(f"\nCountry classification complete:")
        print(f"Countries found: {len(country_map)}")
        for country, configs in sorted(country_map.items()):
            print(f"  {self.get_country_flag(country)} {country.upper()}: {len(configs)} configs")
        
        self.generate_country_summary(country_map)
    
    def generate_country_summary(self, country_map):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        summary = {
            "updated": timestamp,
            "total_countries": len(country_map),
            "countries": {}
        }
        
        for country, configs in country_map.items():
            summary["countries"][country] = {
                "flag": self.get_country_flag(country),
                "count": len(configs),
                "protocols": {}
            }
            categorized = self.categorize_by_protocol(configs)
            for proto, proto_configs in categorized.items():
                summary["countries"][country]["protocols"][proto] = len(proto_configs)
        
        os.makedirs(self.output_base, exist_ok=True)
        
        summary_file = os.path.join(self.output_base, "summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        summary_txt_file = os.path.join(self.output_base, "summary.txt")
        content = f"Country Classification Summary\n"
        content += f"Updated: {timestamp}\n"
        content += "=" * 60 + "\n\n"
        for country in sorted(country_map.keys()):
            flag = self.get_country_flag(country)
            count = len(country_map[country])
            content += f"{flag} {country.upper()}: {count} configs\n"
        with open(summary_txt_file, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    print("=" * 60)
    print("COUNTRY CLASSIFIER")
    print("=" * 60)
    try:
        classifier = CountryClassifier()
        classifier.process_all_configs()
        print("\n✅ Country classification completed successfully")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
