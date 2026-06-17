import os
import re
import json
import base64
import hashlib
import uuid
from datetime import datetime
from urllib.parse import urlparse, unquote

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

    def get_original_tag(self, config_url):
        try:
            if config_url.startswith('ss://'):
                parts = config_url.split('#')
                if len(parts) > 1:
                    return unquote(parts[1]) or ""
                return ""
            elif config_url.startswith('hysteria2://') or config_url.startswith('hy2://'):
                url = urlparse(config_url)
                return unquote(url.fragment) if url.fragment else ""
            elif config_url.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(config_url.replace('vmess://', '')).decode('utf-8')
                    vmess_config = json.loads(decoded)
                    return vmess_config.get('ps', "")
                except:
                    return ""
            elif config_url.startswith('trojan://'):
                url = urlparse(config_url)
                return unquote(url.fragment) if url.fragment else ""
            else:
                url = urlparse(config_url)
                return unquote(url.fragment) if url.fragment else ""
        except:
            return ""

    def is_ip(self, value):
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
        return bool(ip_pattern.match(value))

    def decode_ss_config(self, ss_url):
        try:
            if not ss_url.startswith("ss://"):
                return None

            raw = ss_url[5:]
            raw = raw.split("#")[0]
            raw = raw.split("?")[0]

            try:
                padding = "=" * ((4 - len(raw) % 4) % 4)
                decoded = base64.b64decode(raw + padding).decode("utf-8")

                if "@" in decoded:
                    creds, server_port = decoded.rsplit("@", 1)

                    if ":" in creds and ":" in server_port:
                        method, password = creds.split(":", 1)
                        server, port = server_port.rsplit(":", 1)

                        return {
                            "method": method.strip(),
                            "password": password,
                            "server": server.strip(),
                            "port": int(port),
                            "name": self.get_original_tag(ss_url)
                        }
            except:
                pass

            if "@" in raw:
                encoded_part, server_port = raw.rsplit("@", 1)

                try:
                    padding = "=" * ((4 - len(encoded_part) % 4) % 4)
                    decoded = base64.b64decode(
                        encoded_part + padding
                    ).decode("utf-8")

                    method, password = decoded.split(":", 1)
                    server, port = server_port.rsplit(":", 1)

                    return {
                        "method": method.strip(),
                        "password": password,
                        "server": server.strip(),
                        "port": int(port),
                        "name": self.get_original_tag(ss_url)
                    }
                except:
                    pass

            if "@" in raw and ":" in raw:
                creds, server_port = raw.rsplit("@", 1)

                if ":" in creds and ":" in server_port:
                    method, password = creds.split(":", 1)
                    server, port = server_port.rsplit(":", 1)

                    return {
                        "method": method.strip(),
                        "password": password,
                        "server": server.strip(),
                        "port": int(port),
                        "name": self.get_original_tag(ss_url)
                    }

            return None

        except:
            return None

    def decode_vmess_config(self, vmess_url):
        try:
            base64_data = vmess_url.replace('vmess://', '')
            if len(base64_data) % 4 != 0:
                base64_data += '=' * (4 - len(base64_data) % 4)
            decoded = base64.b64decode(base64_data).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def vless_to_singbox(self, url_str, index, settings=None):
        try:
            if settings is None:
                settings = {}
            url = urlparse(url_str)
            params = dict(pair.split('=') for pair in url.query.split('&') if '=' in pair)
            original_name = self.get_original_tag(url_str) or "VLESS"
            config_name = f"{original_name} #{index + 1}"

            def get_priority_value(setting_key, param_key):
                if settings.get(setting_key) and settings.get(setting_key) != 'none':
                    return settings.get(setting_key)
                return params.get(param_key)

            cleanip_value = get_priority_value('cleanip', 'cleanip')
            domain_value = get_priority_value('domain', 'domain')
            host_value = get_priority_value('domain', 'host') or domain_value
            sni_value = get_priority_value('sni', 'sni')

            cleanip_list = (cleanip_value or '').split(',') if cleanip_value else []
            cleanip_list = [i.strip() for i in cleanip_list if i.strip()]
            final_server = cleanip_list[0] if cleanip_list else url.hostname

            final_sni = sni_value or domain_value or host_value or params.get('sni') or params.get('host') or url.hostname
            if self.is_ip(final_server) and (not final_sni or self.is_ip(final_sni)):
                final_sni = domain_value or host_value or params.get('host') or url.hostname or 'cloudflare.com'

            fingerprint_value = get_priority_value('fingerprint', 'fp') or "chrome"
            alpn_value = get_priority_value('alpn', 'alpn')
            network_type = get_priority_value('network', 'type')
            tls_enabled = get_priority_value('tls', 'security')
            udp_enabled = get_priority_value('udp', 'udp')
            ipver_value = get_priority_value('ipver', 'ipver')

            config = {
                "type": "vless",
                "tag": config_name,
                "server": final_server,
                "server_port": int(url.port) if url.port else 443,
                "uuid": url.username or ''
            }

            if ipver_value and ipver_value != 'none' and ipver_value != 'auto':
                config["domain_resolver"] = {
                    "server": "local-dns",
                    "strategy": "ipv4_only" if ipver_value == "ipv4" else "ipv6_only" if ipver_value == "ipv6" else ipver_value
                }

            if tls_enabled != 'disabled' and (params.get('security') == 'tls' or params.get('security') == 'reality'):
                config["tls"] = {
                    "enabled": True,
                    "server_name": final_sni,
                    "insecure": False,
                    "utls": {
                        "enabled": True,
                        "fingerprint": fingerprint_value
                    }
                }

                if alpn_value and alpn_value != 'none':
                    config["tls"]["alpn"] = [s.strip() for s in alpn_value.split(',') if s.strip()]

                if params.get('security') == "reality" and params.get('pbk'):
                    pbk = params.get('pbk', '').replace('=', '')
                    if re.match(r'^[A-Za-z0-9_-]+$', pbk):
                        reality = {
                            "enabled": True,
                            "public_key": pbk
                        }
                        if params.get('sid') and re.match(r'^[0-9a-fA-F]{2,16}$', params.get('sid')):
                            reality["short_id"] = params.get('sid').lower()
                        config["tls"]["reality"] = reality
            else:
                config["tls"] = {"enabled": False}

            final_network_type = network_type if network_type and network_type != 'none' else params.get('type', 'tcp')

            if udp_enabled != 'disabled':
                config["packet_encoding"] = "xudp"

            if final_network_type == "ws":
                config["transport"] = {
                    "type": "ws",
                    "path": params.get('path', '/'),
                    "headers": {"Host": final_sni}
                }
            elif final_network_type == "grpc":
                config["transport"] = {
                    "type": "grpc",
                    "service_name": domain_value or params.get('serviceName') or "GunService"
                }
            elif final_network_type == "http":
                config["transport"] = {
                    "type": "http",
                    "host": [final_sni],
                    "path": params.get('path', '/')
                }

            return config
        except Exception as e:
            return None

    def ss_to_singbox(self, ss_url, index, settings=None):
        try:
            if settings is None:
                settings = {}
            decoded = self.decode_ss_config(ss_url)
            if not decoded:
                return None

            original_name = decoded.get('name') or "Shadowsocks"
            config_name = f"{original_name} #{index + 1}"

            allowed_methods = [
                "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                "aes-128-cfb", "aes-256-cfb", "chacha20", "chacha20-ietf",
                "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
            ]

            method = decoded.get('method')
            if method not in allowed_methods:
                return None

            return {
                "type": "shadowsocks",
                "tag": config_name,
                "server": decoded.get('server'),
                "server_port": decoded.get('port'),
                "method": method,
                "password": decoded.get('password')
            }
        except:
            return None

    def hysteria2_to_singbox(self, url_str, index, settings=None):
        try:
            if settings is None:
                settings = {}
            if url_str.startswith('hy2://'):
                url_str = url_str.replace('hy2://', 'hysteria2://')
            url = urlparse(url_str)
            params = dict(pair.split('=') for pair in url.query.split('&') if '=' in pair)
            original_name = self.get_original_tag(url_str) or "Hysteria2"
            config_name = f"{original_name} #{index + 1}"

            def get_priority_value(setting_key, param_key):
                if settings.get(setting_key) and settings.get(setting_key) != "none":
                    return settings.get(setting_key)
                return params.get(param_key)

            cleanip_value = get_priority_value("cleanip", "cleanip")
            cleanip_list = (cleanip_value or "").split(",") if cleanip_value else []
            cleanip_list = [i.strip() for i in cleanip_list if i.strip()]
            final_server = cleanip_list[0] if cleanip_list else url.hostname

            domain_value = get_priority_value("domain", "domain")
            host_value = get_priority_value("domain", "host") or domain_value
            sni_value = get_priority_value("sni", "sni") or host_value or domain_value or url.hostname
            fingerprint_value = get_priority_value("fingerprint", "fingerprint") or "chrome"
            alpn_value = get_priority_value("alpn", "alpn")
            ipver_value = get_priority_value("ipver", "ipver")

            config = {
                "type": "hysteria2",
                "tag": config_name,
                "server": final_server,
                "server_port": int(url.port) if url.port else 443,
                "password": url.username or "",
                "tls": {
                    "enabled": True,
                    "server_name": sni_value,
                    "insecure": False,
                    "utls": {
                        "enabled": True,
                        "fingerprint": fingerprint_value
                    }
                }
            }

            if ipver_value and ipver_value != "none" and ipver_value != "auto":
                config["domain_resolver"] = {
                    "server": "local-dns",
                    "strategy": "ipv4_only" if ipver_value == "ipv4" else "ipv6_only" if ipver_value == "ipv6" else ipver_value
                }

            if alpn_value and alpn_value != "none":
                config["tls"]["alpn"] = [v.strip() for v in alpn_value.split(",") if v.strip()]

            obfs_type = params.get("obfs")
            obfs_password = params.get("obfs-password")
            if obfs_type and obfs_password:
                config["obfs"] = {
                    "type": obfs_type,
                    "password": obfs_password
                }

            if params.get("up") or params.get("down"):
                config["up"] = params.get("up") or "100 Mbps"
                config["down"] = params.get("down") or "100 Mbps"

            if params.get("ports"):
                config["ports"] = params.get("ports")

            return config
        except:
            return None

    def vmess_to_singbox(self, vmess_url, index, settings=None):
        try:
            if settings is None:
                settings = {}
            vmess_config = self.decode_vmess_config(vmess_url)
            if not vmess_config:
                return None

            original_name = vmess_config.get('ps') or "VMess"
            config_name = f"{original_name} #{index + 1}"

            def get_priority_value(setting_key, param_key):
                if settings.get(setting_key) and settings.get(setting_key) != "none":
                    return settings.get(setting_key)
                return vmess_config.get(param_key)

            cleanip_value = get_priority_value("cleanip", "add") or vmess_config.get("add")
            cleanip_list = (cleanip_value or "").split(",") if cleanip_value else []
            cleanip_list = [ip.strip() for ip in cleanip_list if ip.strip()]
            final_server = cleanip_list[0] if cleanip_list else vmess_config.get("add")

            domain_value = get_priority_value("domain", "host") or vmess_config.get("host")
            host_value = get_priority_value("domain", "host") or domain_value or vmess_config.get("host")
            sni_value = get_priority_value("sni", "sni") or host_value or domain_value or vmess_config.get("sni") or vmess_config.get("add")

            fingerprint_value = get_priority_value("fingerprint", "fp") or vmess_config.get("fp") or "chrome"
            alpn_value = get_priority_value("alpn", "alpn") or vmess_config.get("alpn")
            network_type = get_priority_value("network", "net") or vmess_config.get("net") or "tcp"
            tls_enabled = get_priority_value("tls", "tls") == "tls"
            ipver_value = get_priority_value("ipver", "ipver")

            config = {
                "type": "vmess",
                "tag": config_name,
                "server": final_server,
                "server_port": int(vmess_config.get("port")) if vmess_config.get("port") else 443,
                "uuid": vmess_config.get("id"),
                "security": vmess_config.get("scy") or "auto",
                "alter_id": int(vmess_config.get("aid") or 0)
            }

            if ipver_value and ipver_value != "none" and ipver_value != "auto":
                config["domain_resolver"] = {
                    "server": "local-dns",
                    "strategy": "ipv4_only" if ipver_value == "ipv4" else "ipv6_only" if ipver_value == "ipv6" else ipver_value
                }

            if tls_enabled:
                config["tls"] = {
                    "enabled": True,
                    "server_name": sni_value,
                    "insecure": False,
                    "utls": {
                        "enabled": True,
                        "fingerprint": fingerprint_value
                    }
                }
                if alpn_value and alpn_value != "none":
                    config["tls"]["alpn"] = [v.strip() for v in alpn_value.split(",") if v.strip()]
            else:
                config["tls"] = {"enabled": False}

            if network_type == "ws":
                config["transport"] = {
                    "type": "ws",
                    "path": vmess_config.get("path") or "/",
                    "headers": {
                        "Host": host_value or sni_value or final_server
                    }
                }
            elif network_type == "h2":
                config["transport"] = {
                    "type": "http",
                    "host": [host_value or sni_value or final_server],
                    "path": vmess_config.get("path") or "/"
                }
            elif network_type == "grpc":
                config["transport"] = {
                    "type": "grpc",
                    "service_name": vmess_config.get("path") or "GunService"
                }

            return config
        except:
            return None

    def trojan_to_singbox(self, trojan_url, index, settings=None):
        try:
            if settings is None:
                settings = {}
            url = urlparse(trojan_url)
            params = dict(pair.split('=') for pair in url.query.split('&') if '=' in pair)
            original_name = self.get_original_tag(trojan_url) or "Trojan"
            config_name = f"{original_name} #{index + 1}"

            def get_priority_value(setting_key, param_key):
                if settings.get(setting_key) and settings.get(setting_key) != "none":
                    return settings.get(setting_key)
                return params.get(param_key)

            cleanip_value = get_priority_value("cleanip", "cleanip")
            cleanip_list = (cleanip_value or "").split(",") if cleanip_value else []
            cleanip_list = [ip.strip() for ip in cleanip_list if ip.strip()]
            final_server = cleanip_list[0] if cleanip_list else url.hostname

            domain_value = get_priority_value("domain", "domain")
            host_value = get_priority_value("domain", "host") or domain_value
            sni_value = get_priority_value("sni", "sni") or host_value or domain_value or params.get("host") or url.hostname
            fingerprint_value = get_priority_value("fingerprint", "fp") or "chrome"
            alpn_value = get_priority_value("alpn", "alpn")
            network_type = get_priority_value("network", "type") or "tcp"
            ipver_value = get_priority_value("ipver", "ipver")

            config = {
                "type": "trojan",
                "tag": config_name,
                "server": final_server,
                "server_port": int(url.port) if url.port else 443,
                "password": url.username or ""
            }

            if ipver_value and ipver_value != "none" and ipver_value != "auto":
                config["domain_resolver"] = {
                    "server": "local-dns",
                    "strategy": "ipv4_only" if ipver_value == "ipv4" else "ipv6_only" if ipver_value == "ipv6" else ipver_value
                }

            config["tls"] = {
                "enabled": True,
                "server_name": sni_value,
                "insecure": False,
                "utls": {
                    "enabled": True,
                    "fingerprint": fingerprint_value
                }
            }

            if alpn_value and alpn_value != "none":
                config["tls"]["alpn"] = [v.strip() for v in alpn_value.split(",") if v.strip()]

            if network_type == "ws":
                config["transport"] = {
                    "type": "ws",
                    "path": params.get("path") or "/",
                    "headers": {
                        "Host": sni_value
                    }
                }
            elif network_type == "grpc":
                config["transport"] = {
                    "type": "grpc",
                    "service_name": params.get("serviceName") or "GunService"
                }

            return config
        except:
            return None

    def convert_config_to_singbox(self, config_str, index, settings=None):
        if config_str.startswith('vless://'):
            return self.vless_to_singbox(config_str, index, settings)
        elif config_str.startswith('ss://'):
            return self.ss_to_singbox(config_str, index, settings)
        elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            return self.hysteria2_to_singbox(config_str, index, settings)
        elif config_str.startswith('vmess://'):
            return self.vmess_to_singbox(config_str, index, settings)
        elif config_str.startswith('trojan://'):
            return self.trojan_to_singbox(config_str, index, settings)
        else:
            return None

    def generate_singbox_outbounds(self, proxies):
        if not proxies:
            return []

        outbounds = []
        for proxy in proxies:
            if proxy.get("type") and proxy.get("tag"):
                outbounds.append(proxy)

        return outbounds

    def generate_singbox_config(self, proxies, source_name, category, tier_name):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        outbounds = self.generate_singbox_outbounds(proxies)

        singbox_config = {
            "log": {
                "level": "info"
            },
            "dns": {
                "servers": []
            },
            "inbounds": [],
            "outbounds": outbounds
        }

        return singbox_config

    def convert_source_configs(self, source_dir, output_dir, source_name):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs(output_dir, exist_ok=True)

        for category in self.categories:
            cat_dir = os.path.join(source_dir, category)
            if not os.path.exists(cat_dir):
                continue

            all_configs = []
            tier_files = {}
            for tier_file in os.listdir(cat_dir):
                if tier_file.endswith('.txt'):
                    filepath = os.path.join(cat_dir, tier_file)
                    configs = self.read_config_file(filepath)
                    if configs:
                        tier_name = tier_file.replace('.txt', '')
                        tier_files[tier_name] = configs
                        all_configs.extend(configs)

            if not all_configs:
                continue

            converted_by_tier = {}
            for tier_name, configs in tier_files.items():
                converted_configs = []
                for idx, config in enumerate(configs):
                    converted = self.convert_config_to_singbox(config, idx)
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
                singbox_config = self.generate_singbox_config(
                    converted_configs, source_name, category, tier_name
                )
                with open(output_filename, 'w', encoding='utf-8') as f:
                    f.write(f"// {source_name.upper()} - {category.upper()} - Tier {tier_name}\n")
                    f.write(f"// Updated: {timestamp}\n")
                    f.write(f"// Count: {len(converted_configs)}\n")
                    json.dump(singbox_config, f, indent=2, ensure_ascii=False)

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
                    converted = self.convert_config_to_singbox(config, idx)
                    if converted:
                        converted_configs.append(converted)

                if not converted_configs:
                    continue

                output_filename = os.path.join(output_all_dir, f"{tier_name}.json")
                singbox_config = self.generate_singbox_config(
                    converted_configs, source_name, "ALL", tier_name
                )
                with open(output_filename, 'w', encoding='utf-8') as f:
                    f.write(f"// {source_name.upper()} - ALL - Tier {tier_name}\n")
                    f.write(f"// Updated: {timestamp}\n")
                    f.write(f"// Count: {len(converted_configs)}\n")
                    json.dump(singbox_config, f, indent=2, ensure_ascii=False)

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
            f.write(f"// {source_name.upper()} JSON Conversion Summary\n")
            f.write(f"// Updated: {timestamp}\n")
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
        all_proxy_tags = set()

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
                                    content = f.read()
                                    content = re.sub(r'^//.*$', '', content, flags=re.MULTILINE)
                                    data = json.loads(content)
                                    if data and 'outbounds' in data:
                                        for proxy in data['outbounds']:
                                            if proxy.get('tag') and proxy.get('tag') not in all_proxy_tags:
                                                all_proxy_tags.add(proxy.get('tag'))
                                                all_proxies.append(proxy)
                            except:
                                continue

                all_dir = os.path.join(source_dir, 'ALL')
                if os.path.exists(all_dir):
                    for json_file in os.listdir(all_dir):
                        if json_file.endswith('.json'):
                            filepath = os.path.join(all_dir, json_file)
                            try:
                                with open(filepath, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    content = re.sub(r'^//.*$', '', content, flags=re.MULTILINE)
                                    data = json.loads(content)
                                    if data and 'outbounds' in data:
                                        for proxy in data['outbounds']:
                                            if proxy.get('tag') and proxy.get('tag') not in all_proxy_tags:
                                                all_proxy_tags.add(proxy.get('tag'))
                                                all_proxies.append(proxy)
                            except:
                                continue

        master_file = os.path.join(output_dir, 'master.json')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        master_config = {
            "log": {
                "level": "info"
            },
            "dns": {
                "servers": []
            },
            "inbounds": [],
            "outbounds": all_proxies
        }

        with open(master_file, 'w', encoding='utf-8') as f:
            f.write(f"// MASTER JSON - ALL CONFIGURATIONS\n")
            f.write(f"// Updated: {timestamp}\n")
            f.write(f"// Total Proxies: {len(all_proxies)}\n")
            json.dump(master_config, f, indent=2, ensure_ascii=False)

def main():
    print("=" * 60)
    print("CONFIG TO JSON (Sing-Box) CONVERTER")
    print("=" * 60)

    try:
        converter = ConfigToJSONConverter()
        converter.convert_all()
        print("\n✅ JSON conversion completed successfully")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    main()
