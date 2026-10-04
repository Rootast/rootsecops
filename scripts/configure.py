#!/usr/bin/env python3
"""Generate private deployment configuration without overwriting an existing one."""

import argparse
import os
from pathlib import Path
import re
import secrets

ROOT = Path(__file__).resolve().parent.parent


def hostname(value):
    value = value.lower()
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise argparse.ArgumentTypeError("Use a hostname only, such as rootsecops.test; no scheme, port, or path.")
    return value


def configure(destination, front_domain, api_domain):
    if front_domain == api_domain:
        raise ValueError("Frontend and API must use different hostnames.")
    values = {
        "FRONT_DOMAIN": front_domain,
        "API_DOMAIN": api_domain,
        "DJANGO_SECRET_KEY": secrets.token_urlsafe(48),
        "ADMIN_PASSWORD": secrets.token_urlsafe(24),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
    }
    lines = []
    for line in (ROOT / ".env.example").read_text().splitlines():
        key, separator, _ = line.partition("=")
        lines.append(f"{key}={values[key]}" if separator and key in values else line)
    # Exclusive creation protects existing credentials; permissions precede the write.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--front-domain", type=hostname, default="rootsecops.test")
    parser.add_argument("--api-domain", type=hostname, default="api.rootsecops.test")
    args = parser.parse_args()
    try:
        configure(ROOT / ".env", args.front_domain, args.api_domain)
    except (FileExistsError, ValueError) as exc:
        parser.exit(1, f"Configuration not changed: {exc}\n")
    print("Created .env with private permissions and random secrets.")
    print("Review it locally for your administrator password and deployment ports.")
    print("Do not commit .env or paste its contents into issues.")


if __name__ == "__main__":
    main()
