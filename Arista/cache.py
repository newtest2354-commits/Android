import os
import json

CACHE_FILE = "output/scanned_cache.txt"
TCP_FILE = "output/tcp_live.txt"
TLS_FILE = "output/tls_live.txt"
HTTPS_FILE = "output/https_live.txt"
FP_FILE = "output/fingerprint_results.txt"
GEO_FILE = "output/geo_cache.json"
HTTPS_META_FILE = "output/https_meta.json"


def ensure_output():
    os.makedirs(
        "output",
        exist_ok=True
    )


def cache_key(
    ip,
    port
):
    return f"{ip}:{port}"


def cache_line(
    ip,
    port,
    status="success"
):
    return f"{ip}:{port}:{status}"


def load_cache():
    ensure_output()

    if not os.path.exists(
        CACHE_FILE
    ):
        return {}

    data = {}

    try:
        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:
                line = line.strip()

                if not line:
                    continue

                parts = line.split(
                    ":"
                )

                if len(parts) < 2:
                    continue

                ip = parts[0]

                try:
                    port = int(
                        parts[1]
                    )
                except:
                    continue

                status = (
                    parts[2]
                    if len(parts) >= 3
                    else "success"
                )

                data[
                    cache_key(
                        ip,
                        port
                    )
                ] = status

    except:
        return {}

    return data


def save_cache(cache):
    ensure_output()

    tmp = (
        CACHE_FILE
        + ".tmp"
    )

    try:
        with open(
            tmp,
            "w",
            encoding="utf-8"
        ) as f:

            for key in sorted(
                cache
            ):
                status = cache[key]

                f.write(
                    f"{key}:{status}\n"
                )

        os.replace(
            tmp,
            CACHE_FILE
        )

    except:
        pass


def already_scanned(
    cache,
    ip,
    port
):
    return (
        cache_key(
            ip,
            port
        )
        in cache
    )


def cache_status(
    cache,
    ip,
    port
):
    return cache.get(
        cache_key(
            ip,
            port
        )
    )


def cache_result(
    cache,
    ip,
    port,
    status="success"
):
    cache[
        cache_key(
            ip,
            port
        )
    ] = status


def cache_count():
    return len(
        load_cache()
    )


def clear_cache():
    ensure_output()

    with open(
        CACHE_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        f.write("")


def read_stage(path):
    ensure_output()

    if not os.path.exists(
        path
    ):
        return []

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:

            return [
                x.strip()
                for x in f
                if x.strip()
            ]

    except:
        return []


def append_stage(
    path,
    items
):
    ensure_output()

    if not items:
        return 0

    count = 0

    try:
        with open(
            path,
            "a",
            encoding="utf-8"
        ) as f:

            for item in items:
                item = str(
                    item
                ).strip()

                if not item:
                    continue

                f.write(
                    item
                    + "\n"
                )

                count += 1

    except:
        return 0

    return count


def dedupe_file(path):
    ensure_output()

    if not os.path.exists(
        path
    ):
        return 0

    tmp = (
        path
        + ".tmp"
    )

    try:
        seen = set()

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as src, open(
            tmp,
            "w",
            encoding="utf-8"
        ) as dst:

            for line in src:
                line = line.strip()

                if (
                    not line
                    or
                    line in seen
                ):
                    continue

                seen.add(
                    line
                )

                dst.write(
                    line
                    + "\n"
                )

        os.replace(
            tmp,
            path
        )

        return len(
            seen
        )

    except:
        return 0


def append_tcp_live(items):
    return append_stage(
        TCP_FILE,
        items
    )


def append_tls_live(items):
    return append_stage(
        TLS_FILE,
        items
    )


def append_https_live(items):
    return append_stage(
        HTTPS_FILE,
        items
    )


def append_fp(items):
    return append_stage(
        FP_FILE,
        items
    )


def optimize_stage_files():
    tcp = dedupe_file(
        TCP_FILE
    )

    tls = dedupe_file(
        TLS_FILE
    )

    https = dedupe_file(
        HTTPS_FILE
    )

    fp = dedupe_file(
        FP_FILE
    )

    return {
        "tcp": tcp,
        "tls": tls,
        "https": https,
        "fp": fp
    }


def read_tcp_live():
    return read_stage(
        TCP_FILE
    )


def read_tls_live():
    return read_stage(
        TLS_FILE
    )


def read_https_live():
    return read_stage(
        HTTPS_FILE
    )


def read_fp():
    return read_stage(
        FP_FILE
    )


def load_geo_cache():
    ensure_output()

    if not os.path.exists(
        GEO_FILE
    ):
        return {}

    try:
        with open(
            GEO_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(
                f
            )
    except:
        return {}


def save_geo_cache(data):
    ensure_output()

    tmp = (
        GEO_FILE
        + ".tmp"
    )

    try:
        with open(
            tmp,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                ensure_ascii=False
            )

        os.replace(
            tmp,
            GEO_FILE
        )

    except:
        pass


def load_https_meta():
    ensure_output()

    if not os.path.exists(
        HTTPS_META_FILE
    ):
        return {}

    try:
        with open(
            HTTPS_META_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(
                f
            )

    except:
        return {}


def save_https_meta(data):
    ensure_output()

    tmp = (
        HTTPS_META_FILE
        + ".tmp"
    )

    try:
        with open(
            tmp,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                ensure_ascii=False
            )

        os.replace(
            tmp,
            HTTPS_META_FILE
        )

    except:
        pass


def https_meta_get(
    ip,
    port
):
    data = load_https_meta()

    return data.get(
        cache_key(
            ip,
            port
        )
    )


def https_meta_store(
    ip,
    port,
    value
):
    data = load_https_meta()

    data[
        cache_key(
            ip,
            port
        )
    ] = value

    save_https_meta(
        data
    )


def geo_cached(ip):
    data = load_geo_cache()

    return data.get(
        ip
    )


def geo_store(
    ip,
    value
):
    data = load_geo_cache()

    data[ip] = value

    save_geo_cache(
        data
    )


if __name__ == "__main__":
    res = optimize_stage_files()

    print(
        f"TCP={res['tcp']} "
        f"TLS={res['tls']} "
        f"HTTPS={res['https']} "
        f"FP={res['fp']}"
    )
