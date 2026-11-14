"""Regenerate harmless synthetic byte samples in this directory."""

from pathlib import Path
import hashlib
import json


def main() -> None:
    """Write deterministic fixture bytes and their provenance hashes."""
    root = Path(__file__).resolve().parent
    samples = {
        "both.bin": b"ORBIT LANDER",
        "orbit-only.bin": b"ORBIT",
        "repeated.bin": "π ORBIT ORBIT".encode("utf-8"),
        "binary.bin": b"\x00\xde\xad\xbe\xef\x01",
        "mixed.bin": "π ORBIT ORBIT LANDER ".encode("utf-8") + b"\xde\xad\xbe\xef",
        "unmatched.bin": b"routine telemetry",
        "empty.bin": b"",
    }
    for name, data in samples.items():
        (root / name).write_bytes(data)
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "note": "Authored synthetic byte samples; inert markers, no malware payload or real-system data.",
                "sha256": {
                    name: hashlib.sha256(data).hexdigest() for name, data in samples.items()
                },
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
