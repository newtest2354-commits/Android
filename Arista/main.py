import os
import argparse
import json
import gc

from downloader import download_sources
from cleaner import clean_ips
from splitter import split_file

from scanner import (
    tcp_scan,
    tls_scan,
    https_scan,
    fingerprint_scan,
    geo_scan
)

from domains import extract_domains, extract_domains_from_results
from validator import validate_domains
from ranker import rank_results

from cache import optimize_stage_files

OUTPUT_DIR = "output"


def ensure_output():
    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def exists(path):
    return (
        os.path.exists(path)
        and
        os.path.getsize(path) > 0
    )


def prepare():
    ensure_output()

    if not exists(
        "output/ip_bank.txt"
    ):
        print(
            "DOWNLOAD START"
        )
        download_sources()

    if not exists(
        "output/clean_ips.txt"
    ):
        print(
            "CLEAN START"
        )
        clean_ips()


def cleanup_memory():
    gc.collect()


def clean_stage_files_before_stage():
    stage_files = [
        "output/tcp_live.txt",
        "output/tls_live.txt",
        "output/https_live.txt",
        "output/fingerprint_results.txt",
        "output/https_meta.json",
        "output/current_part.txt"
    ]
    for f in stage_files:
        if os.path.exists(f):
            os.remove(f)
            print(f"REMOVED STAGE: {f}")


def run_tcp():
    prepare()

    print(
        "ROLLING SPLIT"
    )

    clean_stage_files_before_stage()

    input_file = split_file()

    if not exists(
        input_file
    ):
        print(
            "NO PART"
        )
        return

    print(
        "TCP START"
    )

    tcp_scan(
        input_file
    )

    print(
        "TCP DONE"
    )

    cleanup_memory()


def run_tls():
    prepare()

    if not exists(
        "output/tcp_live.txt"
    ):
        print(
            "NO TCP CACHE"
        )
        return

    print(
        "TLS START"
    )

    tls_scan()

    print(
        "TLS DONE"
    )

    cleanup_memory()


def run_https():
    prepare()

    if not exists(
        "output/tls_live.txt"
    ):
        print(
            "NO TLS CACHE"
        )
        return

    print(
        "HTTPS START"
    )

    https_scan()

    print(
        "HTTPS DONE"
    )

    cleanup_memory()


def run_fp():
    prepare()

    if not exists(
        "output/https_live.txt"
    ):
        print(
            "NO HTTPS CACHE"
        )
        return

    print(
        "FP START"
    )

    fingerprint_scan()

    print(
        "FP DONE"
    )

    cleanup_memory()


def run_geo():
    prepare()

    if not exists(
        "output/fingerprint_results.txt"
    ):
        print(
            "NO FP CACHE"
        )
        return

    print(
        "GEO START"
    )

    geo_scan()

    print(
        "GEO DONE"
    )

    cleanup_memory()


def run_finalize():
    prepare()

    if not exists(
        "output/results.txt"
    ):
        print(
            "NO RESULTS"
        )
        return

    print(
        "OPTIMIZE CACHE"
    )

    optimize_stage_files()

    if exists(
        "output/results.txt"
    ):
        print(
            "DOMAIN EXTRACT"
        )
        extract_domains_from_results()

    if exists(
        "output/domains_raw.txt"
    ):
        print(
            "DOMAIN VALIDATE"
        )
        validate_domains()

    print(
        "RANK START"
    )

    rank_results()

    print(
        "FINAL DONE"
    )

    cleanup_memory()


def main():
    ensure_output()

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--tcp",
        action="store_true"
    )

    parser.add_argument(
        "--tls",
        action="store_true"
    )

    parser.add_argument(
        "--https",
        action="store_true"
    )

    parser.add_argument(
        "--fp",
        action="store_true"
    )

    parser.add_argument(
        "--geo",
        action="store_true"
    )

    parser.add_argument(
        "--finalize",
        action="store_true"
    )

    args = parser.parse_args()

    load_config()

    print(
        "ARISTA START"
    )

    if args.tcp:
        run_tcp()

    elif args.tls:
        run_tls()

    elif args.https:
        run_https()

    elif args.fp:
        run_fp()

    elif args.geo:
        run_geo()

    elif args.finalize:
        run_finalize()

    else:
        run_tcp()

    print(
        "ARISTA DONE"
    )


if __name__ == "__main__":
    main()
