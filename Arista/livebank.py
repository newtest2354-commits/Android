import os

LIVE_BANK_FILE = "output/live_bank.txt"

def ensure_output():
    os.makedirs(
        "output",
        exist_ok=True
    )

def normalize(item):
    return str(
        item
    ).strip()

def read_live_bank():
    ensure_output()

    if not os.path.exists(
        LIVE_BANK_FILE
    ):
        return set()

    try:
        with open(
            LIVE_BANK_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            return {
                normalize(line)
                for line in f
                if normalize(line)
            }
    except:
        return set()

def live_exists(item):
    item = normalize(item)

    if not item:
        return False

    return item in read_live_bank()

def append_live(items):
    ensure_output()

    existing = read_live_bank()
    new_items = []

    for item in items:
        item = normalize(item)

        if not item:
            continue

        if item in existing:
            continue

        existing.add(item)
        new_items.append(item)

    if not new_items:
        return 0

    try:
        with open(
            LIVE_BANK_FILE,
            "a",
            encoding="utf-8"
        ) as f:
            for item in new_items:
                f.write(
                    item + "\n"
                )

        return len(new_items)

    except:
        return 0

def replace_live(items):
    ensure_output()

    data = sorted(
        {
            normalize(x)
            for x in items
            if normalize(x)
        }
    )

    try:
        with open(
            LIVE_BANK_FILE,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(
                "\n".join(data)
            )

        return len(data)

    except:
        return 0

def dedupe_live_bank():
    ensure_output()

    data = sorted(
        read_live_bank()
    )

    try:
        with open(
            LIVE_BANK_FILE,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(
                "\n".join(data)
            )

        return len(data)

    except:
        return 0

def live_count():
    return len(
        read_live_bank()
    )

def read_live_lines():
    return sorted(
        read_live_bank()
    )

def clear_live_bank():
    ensure_output()

    with open(
        LIVE_BANK_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        f.write("")

if __name__ == "__main__":
    count = dedupe_live_bank()

    print(
        f"LIVE={count}"
    )
