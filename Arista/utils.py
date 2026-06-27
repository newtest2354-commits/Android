TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}

def is_tls_port(port):
    return port in TLS_PORTS

def safe_lower(value):
    if value is None:
        return ""
    return str(value).strip().lower()

def unique_sorted(values):
    return sorted(set(values))

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except:
        return []

def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
