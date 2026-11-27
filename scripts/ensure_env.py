"""Generate .env from .env.example with fresh cryptographic secrets if missing."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def generate_env(force: bool = False) -> Path:
    if ENV_FILE.exists() and not force:
        print(f"{ENV_FILE} already exists; keeping existing configuration.")
        return ENV_FILE

    template = ENV_EXAMPLE.read_text(encoding="utf-8")
    replacements = {
        "__GENERATE_HEX_64__": lambda: secrets.token_hex(32),
        "__GENERATE_B64_32__": lambda: base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "__GENERATE_DEMO_PW__": lambda: "ThreatDemo!2026",
    }

    lines = []
    for line in template.splitlines():
        out = line
        for token, factory in replacements.items():
            if token in out:
                out = out.replace(token, factory())
        lines.append(out)

    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Created {ENV_FILE} with freshly generated cryptographic keys.")
    return ENV_FILE


if __name__ == "__main__":
    generate_env()
