"""Generate local secrets without replacing existing configuration."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    values = {
        "ZT_JWT_SECRET": secrets.token_urlsafe(48),
        "ZT_ADMIN_PASSWORD": secrets.token_urlsafe(20),
        "ZT_DEMO_PASSWORD": secrets.token_urlsafe(20),
        "ZT_DATABASE_PASSWORD": secrets.token_hex(24),
    }
    content = (ROOT / ".env.example").read_text().splitlines()
    for i, line in enumerate(content):
        key = line.split("=", 1)[0]
        if key in values:
            content[i] = f"{key}={values[key]}"
    try:
        with open(
            ROOT / ".env", "x", opener=lambda path, flags: os.open(path, flags, 0o600)
        ) as handle:
            handle.write("\n".join(content) + "\n")
    except FileExistsError:
        print(".env already exists; left unchanged.")
        return
    print("Created .env with unique secrets (permissions 0600). Do not commit or share it.")
    print("Administrator: admin / ZT_ADMIN_PASSWORD in .env")
    print("Demo users: alice, bob, operator / ZT_DEMO_PASSWORD in .env")


if __name__ == "__main__":
    main()
