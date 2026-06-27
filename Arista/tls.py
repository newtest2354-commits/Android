import ssl
import socket
import hashlib
import json
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def cert_meta(cert_bin, cert):
    try:
        sha256 = hashlib.sha256(cert_bin).hexdigest()
    except:
        sha256 = ""
    issuer = ""
    expire = ""
    try:
        issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "")
    except:
        pass
    try:
        expire = cert.get("notAfter", "")
    except:
        pass
    return {
        "issuer": issuer,
        "expire": expire,
        "sha256": sha256
    }

def tls_check(ip, port, timeout=3):
    cfg = load_config()
    sni_hosts = cfg.get("sni_hosts", [])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except:
        pass

    for sni in sni_hosts:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    meta = cert_meta(cert_bin, cert)
                    return True, {
                        "cert": cert,
                        "meta": meta,
                        "alpn": ssock.selected_alpn_protocol(),
                        "sni": sni
                    }
        except:
            continue
    return False, None
