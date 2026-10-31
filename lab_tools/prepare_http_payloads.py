"""Gera somente arquivos sinteticos locais para o servidor HTTP do Kali-LAB."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


PAYLOADS = {
    "small_16k.bin": 16 * 1024,
    "medium_256k.bin": 256 * 1024,
    "large_2m.bin": 2 * 1024 * 1024,
}


def prepare(directory: Path) -> dict:
    """Exige pasta nova; nao altera o conteudo anterior de /lab-http."""
    directory.mkdir(parents=True, exist_ok=False)
    pattern = b"TCC2026-BENIGN-HTTP-DATA\n"
    files = []
    for name, size in PAYLOADS.items():
        content = (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]
        with (directory / name).open("xb") as stream:
            stream.write(content)
        files.append({"name": name, "size_bytes": size,
                      "sha256": hashlib.sha256(content).hexdigest()})
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "synthetic HTTP downloads in isolated lab; not production traffic",
        "files": files,
    }
    with (directory / "payload_manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.directory), indent=2))
