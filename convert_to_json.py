# convert_to_json.py
import os
import re
import json
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

ALLOWED_SS_CIPHERS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "aes-128-cfb",
    "aes-256-cfb",
    "chacha20",
    "chacha20-ietf"
}

def safe_b64_decode(data: str):
    try:
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None

def decode_ss_config(ss_url: str):
    try:
        raw = ss_url.replace("ss://", "").split("#")[0]
        if "@" not in raw:
            return None
        method_password, server_port = raw.split("@", 1)
        decoded = safe_b64_decode(method_password)
        if not decoded or ":" not in decoded:
            return None
        method, password = decoded.split(":", 1)
        if method not in ALLOWED_SS_CIPHERS:
            return None
        if ":" not in server_port:
            return None
        server, port = server_port.split(":", 1)
        if not port.isdigit():
            return None
        name = ""
        if "#" in ss_url:
            name = unquote(ss_url.split("#", 1)[1])
        return {
            "method": method,
            "password": password,
            "server": server,
            "port": int(port),
            "name": name
        }
    except:
        return None

def decode_vmess(raw: str):
    try:
        data = raw.replace("vmess://", "")
        decoded = base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="ignore")
        return json.loads(decoded)
    except:
        return None

def vless_to_singbox(index: int, raw: str):
    try:
        if not raw.startswith("vless://"):
            return None

        parsed = urlparse(raw)
        qs = parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port or not parsed.username:
            return None
        if not UUID_RE.match(parsed.username):
            return None

        name = f"{unquote(parsed.fragment or 'VLESS')} #{index + 1}"
        network = qs.get("type", ["tcp"])[0]
        security = qs.get("security", ["none"])[0]

        config = {
            "type": "vless",
            "tag": name,
            "server": parsed.hostname,
            "server_port": int(parsed.port),
            "uuid": parsed.username,
        }

        if security in ("tls", "reality"):
            tls = {
                "enabled": True,
                "server_name": qs.get("sni", [parsed.hostname])[0],
                "insecure": False,
                "utls": {
                    "enabled": True,
                    "fingerprint": qs.get("fp", ["chrome"])[0]
                }
            }

            if security == "reality":
                pbk = qs.get("pbk", [None])[0]
                if not pbk:
                    return None

                tls["reality"] = {
                    "enabled": True,
                    "public_key": pbk.replace("=", "")
                }

                sid = qs.get("sid", [None])[0]
                if sid and re.fullmatch(r"^[0-9a-fA-F]{2,32}$", sid):
                    tls["reality"]["short_id"] = sid.lower()

            config["tls"] = tls
        else:
            config["tls"] = {"enabled": False}

        if network == "ws":
            config["transport"] = {
                "type": "ws",
                "path": qs.get("path", ["/"])[0],
                "headers": {"Host": qs.get("host", [parsed.hostname])[0]}
            }
        elif network == "grpc":
            config["transport"] = {
                "type": "grpc",
                "service_name": qs.get("serviceName", ["GunService"])[0]
            }
        elif network == "http":
            config["transport"] = {
                "type": "http",
                "host": [qs.get("host", [parsed.hostname])[0]],
                "path": qs.get("path", ["/"])[0]
            }

        return config
    except:
        return None

def ss_to_singbox(index: int, raw: str):
    d = decode_ss_config(raw)
    if not d:
        return None
    name = f"{d['name'] or 'SS'} #{index + 1}"
    return {
        "type": "shadowsocks",
        "tag": name,
        "server": d["server"],
        "server_port": d["port"],
        "method": d["method"],
        "password": d["password"]
    }

def vmess_to_singbox(index: int, raw: str):
    c = decode_vmess(raw)
    if not c:
        return None
    if not all(k in c for k in ("add", "port", "id")):
        return None

    name = f"{c.get('ps', 'VMess')} #{index + 1}"

    try:
        port = int(c["port"])
    except:
        return None

    config = {
        "type": "vmess",
        "tag": name,
        "server": c["add"],
        "server_port": port,
        "uuid": c["id"],
        "security": c.get("scy", "auto"),
        "alter_id": int(c.get("aid", 0))
    }

    if c.get("tls") == "tls":
        config["tls"] = {
            "enabled": True,
            "server_name": c.get("sni", c.get("host", c["add"])),
            "insecure": False,
            "utls": {
                "enabled": True,
                "fingerprint": c.get("fp", "chrome")
            }
        }
    else:
        config["tls"] = {"enabled": False}

    network = c.get("net", "tcp")

    if network == "ws":
        config["transport"] = {
            "type": "ws",
            "path": c.get("path", "/"),
            "headers": {"Host": c.get("host", c["add"])}
        }
    elif network in ("h2", "http"):
        config["transport"] = {
            "type": "http",
            "host": [c.get("host", c["add"])],
            "path": c.get("path", "/")
        }
    elif network == "grpc":
        config["transport"] = {
            "type": "grpc",
            "service_name": c.get("path", "GunService").lstrip("/")
        }

    return config

def trojan_to_singbox(index: int, raw: str):
    try:
        p = urlparse(raw)
        if not p.hostname or not p.port or not p.username:
            return None

        q = parse_qs(p.query)
        name = f"{unquote(p.fragment or 'Trojan')} #{index + 1}"

        config = {
            "type": "trojan",
            "tag": name,
            "server": p.hostname,
            "server_port": int(p.port),
            "password": p.username,
            "tls": {
                "enabled": True,
                "server_name": q.get("sni", [p.hostname])[0],
                "insecure": False,
                "utls": {
                    "enabled": True,
                    "fingerprint": q.get("fp", ["chrome"])[0]
                }
            }
        }

        network = q.get("type", ["tcp"])[0]

        if network == "ws":
            config["transport"] = {
                "type": "ws",
                "path": q.get("path", ["/"])[0],
                "headers": {"Host": q.get("sni", [p.hostname])[0]}
            }
        elif network == "grpc":
            config["transport"] = {
                "type": "grpc",
                "service_name": q.get("serviceName", ["GunService"])[0]
            }

        return config
    except:
        return None

def hysteria2_to_singbox(index: int, raw: str):
    try:
        raw = raw.replace("hy2://", "hysteria2://")
        p = urlparse(raw)

        if not p.hostname or not p.port:
            return None

        q = parse_qs(p.query)
        name = f"{unquote(p.fragment or 'Hysteria2')} #{index + 1}"

        config = {
            "type": "hysteria2",
            "tag": name,
            "server": p.hostname,
            "server_port": int(p.port),
            "password": p.username or "",
            "tls": {
                "enabled": True,
                "server_name": q.get("sni", [p.hostname])[0],
                "insecure": False,
                "utls": {
                    "enabled": True,
                    "fingerprint": q.get("fingerprint", ["chrome"])[0]
                }
            }
        }

        obfs = q.get("obfs", [None])[0]
        obfs_pass = q.get("obfs-password", [None])[0]
        if obfs and obfs_pass:
            config["obfs"] = {
                "type": obfs,
                "password": obfs_pass
            }

        if q.get("up"):
            config["up"] = q["up"][0]
        if q.get("down"):
            config["down"] = q["down"][0]
        if q.get("ports"):
            config["ports"] = q["ports"][0]

        return config
    except:
        return None

def tuic_to_singbox(index: int, raw: str):
    try:
        p = urlparse(raw)
        if not p.hostname or not p.port or not p.username:
            return None

        q = parse_qs(p.query)
        name = f"{unquote(p.fragment or 'Tuic')} #{index + 1}"

        config = {
            "type": "tuic",
            "tag": name,
            "server": p.hostname,
            "server_port": int(p.port),
            "uuid": p.username,
            "password": q.get("password", [""])[0],
            "congestion_control": q.get("congestion_control", ["bbr"])[0],
            "udp_relay_mode": q.get("udp_relay_mode", ["native"])[0],
            "zero_rtt_handshake": q.get("zero_rtt_handshake", ["false"])[0].lower() == "true",
            "tls": {
                "enabled": True,
                "server_name": q.get("sni", [p.hostname])[0],
                "insecure": False,
                "utls": {
                    "enabled": True,
                    "fingerprint": q.get("fp", ["chrome"])[0]
                }
            }
        }

        return config
    except:
        return None

def wireguard_to_singbox(index: int, raw: str):
    try:
        p = urlparse(raw)
        if not p.hostname or not p.port:
            return None

        q = parse_qs(p.query)
        name = f"{unquote(p.fragment or 'WireGuard')} #{index + 1}"

        config = {
            "type": "wireguard",
            "tag": name,
            "server": p.hostname,
            "server_port": int(p.port),
            "private_key": q.get("private_key", [""])[0],
            "peer_public_key": q.get("public_key", [""])[0],
            "reserved": q.get("reserved", [""])[0].split(",") if q.get("reserved") else [],
            "pre_shared_key": q.get("pre_shared_key", [""])[0],
            "mtu": int(q.get("mtu", [1420])[0]),
            "network": q.get("network", ["0.0.0.0/0"])[0],
            "dns": q.get("dns", [""])[0]
        }

        return config
    except:
        return None

def convert_config_to_singbox(config_str, index):
    if config_str.startswith('vless://'):
        return vless_to_singbox(index, config_str)
    elif config_str.startswith('ss://'):
        return ss_to_singbox(index, config_str)
    elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
        return hysteria2_to_singbox(index, config_str)
    elif config_str.startswith('vmess://'):
        return vmess_to_singbox(index, config_str)
    elif config_str.startswith('trojan://'):
        return trojan_to_singbox(index, config_str)
    elif config_str.startswith('tuic://'):
        return tuic_to_singbox(index, config_str)
    elif config_str.startswith('wireguard://'):
        return wireguard_to_singbox(index, config_str)
    else:
        return None

class ConfigToJSONConverter:
    def __init__(self):
        self.categories = [
            'vmess', 'vless', 'trojan', 'ss',
            'hysteria2', 'hysteria', 'tuic',
            'wireguard', 'other'
        ]
        self.tiers = [50, 100, 150, 200, 250, 300, 400, 500, "ALL"]

    def read_config_file(self, filepath):
        if not os.path.exists(filepath):
            return []
        configs = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        return configs

    def convert_source_configs(self, source_dir, output_dir, source_name):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs(output_dir, exist_ok=True)

        for category in self.categories:
            cat_dir = os.path.join(source_dir, category)
            if not os.path.exists(cat_dir):
                continue

            tier_files = {}
            for tier_file in os.listdir(cat_dir):
                if tier_file.endswith('.txt'):
                    filepath = os.path.join(cat_dir, tier_file)
                    configs = self.read_config_file(filepath)
                    if configs:
                        tier_name = tier_file.replace('.txt', '')
                        tier_files[tier_name] = configs

            if not tier_files:
                continue

            converted_by_tier = {}
            for tier_name, configs in tier_files.items():
                converted_configs = []
                for idx, config in enumerate(configs):
                    converted = convert_config_to_singbox(config, idx)
                    if converted:
                        converted_configs.append(converted)
                if converted_configs:
                    converted_by_tier[tier_name] = converted_configs

            if not converted_by_tier:
                continue

            output_cat_dir = os.path.join(output_dir, category)
            os.makedirs(output_cat_dir, exist_ok=True)

            for tier_name, converted_configs in converted_by_tier.items():
                output_filename = os.path.join(output_cat_dir, f"{tier_name}.json")
                json_content = {
                    'source': source_name.upper(),
                    'category': category.upper(),
                    'tier': tier_name,
                    'updated': timestamp,
                    'count': len(converted_configs),
                    'proxies': converted_configs
                }
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(json_content, f, indent=2, ensure_ascii=False)

        self.convert_all_tiers(source_dir, output_dir, source_name)
        self.generate_summary_json(source_dir, output_dir, source_name)

    def convert_all_tiers(self, source_dir, output_dir, source_name):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        all_dir = os.path.join(source_dir, 'ALL')
        if not os.path.exists(all_dir):
            return

        output_all_dir = os.path.join(output_dir, 'ALL')
        os.makedirs(output_all_dir, exist_ok=True)

        for tier_file in os.listdir(all_dir):
            if tier_file.endswith('.txt'):
                filepath = os.path.join(all_dir, tier_file)
                configs = self.read_config_file(filepath)
                if not configs:
                    continue

                tier_name = tier_file.replace('.txt', '')
                converted_configs = []
                for idx, config in enumerate(configs):
                    converted = convert_config_to_singbox(config, idx)
                    if converted:
                        converted_configs.append(converted)

                if not converted_configs:
                    continue

                output_filename = os.path.join(output_all_dir, f"{tier_name}.json")
                json_content = {
                    'source': source_name.upper(),
                    'category': 'ALL',
                    'tier': tier_name,
                    'updated': timestamp,
                    'count': len(converted_configs),
                    'proxies': converted_configs
                }
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(json_content, f, indent=2, ensure_ascii=False)

    def generate_summary_json(self, source_dir, output_dir, source_name):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        summary_data = {
            'source': source_name.upper(),
            'updated': timestamp,
            'categories': {}
        }

        for category in self.categories:
            cat_dir = os.path.join(source_dir, category)
            if os.path.exists(cat_dir):
                category_data = {}
                for tier_file in os.listdir(cat_dir):
                    if tier_file.endswith('.txt'):
                        tier_name = tier_file.replace('.txt', '')
                        filepath = os.path.join(cat_dir, tier_file)
                        configs = self.read_config_file(filepath)
                        category_data[tier_name] = len(configs)
                if category_data:
                    summary_data['categories'][category] = category_data

        all_dir = os.path.join(source_dir, 'ALL')
        if os.path.exists(all_dir):
            all_data = {}
            for tier_file in os.listdir(all_dir):
                if tier_file.endswith('.txt'):
                    tier_name = tier_file.replace('.txt', '')
                    filepath = os.path.join(all_dir, tier_file)
                    configs = self.read_config_file(filepath)
                    all_data[tier_name] = len(configs)
            if all_data:
                summary_data['ALL'] = all_data

        output_filename = os.path.join(output_dir, f"{source_name}_summary.json")
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)

    def convert_all(self):
        sources = [
            ('configs.txt/combined', 'config.json/combined', 'combined'),
            ('configs.txt/telegram', 'config.json/telegram', 'telegram'),
            ('configs.txt/github', 'config.json/github', 'github')
        ]

        for source_dir, output_dir, source_name in sources:
            if os.path.exists(source_dir):
                self.convert_source_configs(source_dir, output_dir, source_name)

        self.create_master_json()

    def create_master_json(self):
        output_dir = 'config.json'
        os.makedirs(output_dir, exist_ok=True)

        all_proxies = []
        for source in ['combined', 'telegram', 'github']:
            source_dir = os.path.join(output_dir, source)
            if not os.path.exists(source_dir):
                continue

            for category in self.categories:
                cat_dir = os.path.join(source_dir, category)
                if os.path.exists(cat_dir):
                    for json_file in os.listdir(cat_dir):
                        if json_file.endswith('.json'):
                            filepath = os.path.join(cat_dir, json_file)
                            try:
                                with open(filepath, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    if data and 'proxies' in data:
                                        all_proxies.extend(data['proxies'])
                            except:
                                continue

                all_dir = os.path.join(source_dir, 'ALL')
                if os.path.exists(all_dir):
                    for json_file in os.listdir(all_dir):
                        if json_file.endswith('.json'):
                            filepath = os.path.join(all_dir, json_file)
                            try:
                                with open(filepath, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    if data and 'proxies' in data:
                                        all_proxies.extend(data['proxies'])
                            except:
                                continue

        master_file = os.path.join(output_dir, 'master.json')
        if all_proxies:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            master_content = {
                'source': 'MASTER',
                'updated': timestamp,
                'total': len(all_proxies),
                'proxies': all_proxies
            }
            with open(master_file, 'w', encoding='utf-8') as f:
                json.dump(master_content, f, indent=2, ensure_ascii=False)

def main():
    print("=" * 60)
    print("CONFIG TO JSON (Sing-Box) CONVERTER")
    print("=" * 60)

    try:
        converter = ConfigToJSONConverter()
        converter.convert_all()
        print("JSON conversion completed successfully")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
