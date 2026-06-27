import os

CURSOR_FILE = "output/scan_cursor.txt"

def ensure_output():
    os.makedirs("output", exist_ok=True)

def load_cursor():
    ensure_output()
    if not os.path.exists(CURSOR_FILE):
        return 0
    try:
        with open(CURSOR_FILE, "r", encoding="utf-8") as f:
            value = f.read().strip()
            if not value:
                return 0
            return int(value)
    except:
        return 0

def save_cursor(value):
    ensure_output()
    try:
        value = int(value)
    except:
        value = 0
    if value < 0:
        value = 0
    with open(CURSOR_FILE, "w", encoding="utf-8") as f:
        f.write(str(value))

def reset_cursor():
    save_cursor(0)

def cursor_exists():
    return os.path.exists(CURSOR_FILE)

if __name__ == "__main__":
    print(load_cursor())
