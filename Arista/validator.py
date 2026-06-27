import dns.resolver
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)

INPUT_FILE = "output/domains_raw.txt"
OUTPUT_FILE = "output/domains.txt"

THREADS = 100
DNS_TIMEOUT = 2
DNS_LIFETIME = 3


def valid_domain(domain):
    if not domain:
        return False

    if "*" in domain:
        return False

    if "." not in domain:
        return False

    return True


def resolver():
    r = dns.resolver.Resolver()

    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_LIFETIME

    return r


def resolve_domain(domain):
    try:
        r = resolver()

        r.resolve(
            domain,
            "A"
        )

        return domain

    except:
        return None


def load_domains():
    try:
        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return [
                x.strip().lower()
                for x in f
                if x.strip()
            ]

    except:
        return []


def validate_domains():
    domains = load_domains()

    domains = sorted(
        set(
            d
            for d in domains
            if valid_domain(d)
        )
    )

    print(
        f"INPUT={len(domains)} "
        f"THREADS={THREADS}"
    )

    good = set()

    with ThreadPoolExecutor(
        max_workers=THREADS
    ) as ex:

        futures = [
            ex.submit(
                resolve_domain,
                domain
            )
            for domain in domains
        ]

        for fut in as_completed(
            futures
        ):
            try:
                res = fut.result()

                if res:
                    good.add(res)

            except:
                continue

    good = sorted(good)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(good)
        )

    print(
        f"VALID={len(good)}"
    )


if __name__ == "__main__":
    validate_domains()
