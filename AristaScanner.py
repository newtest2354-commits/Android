import asyncio
import socket
import ssl
import aiohttp
import ipaddress
import random
import json
import time
import os
from collections import OrderedDict

STATE_FILE = "state.json"

CIDR_SOURCES = [
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Afranet.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/AsiaTech-ip-CF.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Iran%20Telecommunication%20Company%20PJS.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Mizban%20Dade.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/MnageIt.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_1.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_2.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Noyan%20Abr%20Arvan%20Co_3.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Pars%20Abr.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Pars%20Online.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Respina.txt",
    "https://raw.githubusercontent.com/rezakhosh78/RKh-CF-Scanner/main/ip-ranges/iran/Tookan.txt"
]

PORTS = [443, 8443, 2053, 2087, 2096, 80, 8080, 8880, 2082, 2083, 4443]

MAX_PROXY_POOL = 2000
TCP_TIMEOUT = 1.2
TLS_TIMEOUT = 3
DECAY_HALF_LIFE = 6 * 60 * 60

MAX_CONCURRENCY = 800
sem = asyncio.Semaphore(MAX_CONCURRENCY)

STATE = {"bootstrapped": False}


def load_state():
    global STATE
    if os.path.exists(STATE_FILE):
        STATE = json.load(open(STATE_FILE))


def save_state():
    json.dump(STATE, open(STATE_FILE, "w"))


load_state()


class LRUCache:
    def __init__(self, size=10000):
        self.data = OrderedDict()
        self.size = size

    def get(self, k):
        v = self.data.get(k)
        if v:
            self.data.move_to_end(k)
        return v

    def set(self, k, v):
        self.data[k] = v
        self.data.move_to_end(k)
        if len(self.data) > self.size:
            self.data.popitem(last=False)


cache = LRUCache()


SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.set_alpn_protocols(["h2", "http/1.1"])


class ProxyPool:
    def __init__(self):
        self.pool = {}

    def score(self, r):
        base = r.get("avg_latency", 9999)
        age = time.time() - r.get("last_seen", time.time())
        decay = min(age / DECAY_HALF_LIFE, 0.7)
        return (1000 - base) * (1 - decay)

    def update(self, r):
        key = f"{r['ip']}:{r['port']}"
        r["last_seen"] = time.time()

        if key in self.pool:
            old = self.pool[key]
            new_lat = r["latency"]
            old_avg = old.get("avg_latency", new_lat)
            r["avg_latency"] = old_avg * 0.7 + new_lat * 0.3
            r["fails"] = old.get("fails", 0)
        else:
            r["avg_latency"] = r["latency"]
            r["fails"] = 0

        self.pool[key] = r

        if len(self.pool) > MAX_PROXY_POOL:
            self.pool = dict(
                sorted(self.pool.items(), key=lambda x: self.score(x[1]), reverse=True)[:MAX_PROXY_POOL]
            )

    def mark_fail(self, ip, port):
        key = f"{ip}:{port}"
        if key in self.pool:
            self.pool[key]["fails"] = self.pool[key].get("fails", 0) + 1
            if self.pool[key]["fails"] >= 3:
                del self.pool[key]

    def get_all(self):
        return list(self.pool.values())


proxy_pool = ProxyPool()


async def fetch_cidrs():
    ips = set()
    limit = 5000 if not STATE["bootstrapped"] else 1500

    async with aiohttp.ClientSession() as session:
        for url in CIDR_SOURCES:
            if len(ips) >= limit:
                break
            try:
                async with session.get(url, timeout=10) as r:
                    text = await r.text()

                for line in text.splitlines():
                    if len(ips) >= limit:
                        break
                    if "/" not in line:
                        continue

                    try:
                        net = ipaddress.ip_network(line.strip(), strict=False)
                        host_count = max(1, net.num_addresses - 2)
                        sample_count = min(10, host_count)

                        offsets = random.sample(range(1, host_count + 1), sample_count)

                        for off in offsets:
                            if len(ips) >= limit:
                                break
                            ips.add(str(net.network_address + off))

                    except:
                        continue

            except:
                continue

    return list(ips)[:limit]


async def tcp_check(ip, port):
    try:
        await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=TCP_TIMEOUT
        )
        return True
    except:
        return False


async def https_probe(ip, port):
    key = f"{ip}:{port}"
    cached = cache.get(key)
    if cached:
        return cached

    try:
        start = time.time()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX),
            timeout=TLS_TIMEOUT
        )

        latency = int((time.time() - start) * 1000)

        writer.close()
        await writer.wait_closed()

        res = {
            "ip": ip,
            "port": port,
            "latency": latency,
        }

        cache.set(key, res)
        return res

    except:
        return None


async def process_ip(ip):
    async with sem:
        open_ports = []

        tcp_results = await asyncio.gather(
            *(tcp_check(ip, p) for p in PORTS)
        )

        for i, ok in enumerate(tcp_results):
            if ok:
                open_ports.append(PORTS[i])

        tls_results = await asyncio.gather(
            *(https_probe(ip, p) for p in open_ports)
        )

        for r in tls_results:
            if r:
                proxy_pool.update(r)

        for p in PORTS:
            if p not in open_ports:
                proxy_pool.mark_fail(ip, p)


async def run_cycle():
    ips = await fetch_cidrs()

    await asyncio.gather(*(process_ip(ip) for ip in ips))

    results = sorted(
        proxy_pool.get_all(),
        key=lambda x: proxy_pool.score(x),
        reverse=True
    )[:MAX_PROXY_POOL]

    with open("results.json", "w") as f:
        json.dump(results, f, indent=2)

    if not STATE["bootstrapped"]:
        STATE["bootstrapped"] = True
        save_state()

    print("RESULTS:", len(results))


async def scheduler():
    while True:
        await run_cycle()
        await asyncio.sleep(3 * 60 * 60)


if __name__ == "__main__":
    asyncio.run(scheduler())
