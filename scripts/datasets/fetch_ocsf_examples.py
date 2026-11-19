from __future__ import annotations

"""Synchronize standard OCSF & adversary telemetry samples into tests/fixtures/external/.

Sources:
- OCSF official examples: https://github.com/ocsf/examples
- OTRF Security-Datasets (Mordor): https://github.com/OTRF/Security-Datasets
"""

import argparse
from pathlib import Path
import urllib.request

EXTERNAL_DIR = Path("tests/fixtures/external")

CATALOG: dict[str, str] = {
    "ocsf_readme": "https://raw.githubusercontent.com/ocsf/examples/main/README.md",
}


def sync_samples(dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    for name, url in CATALOG.items():
        out = dest / f"{name}.txt"
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310
            out.write_bytes(resp.read())
        saved.append(out)
    return saved


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch external OCSF / OTRF sample datasets")
    parser.add_argument("--dest", default=str(EXTERNAL_DIR))
    args = parser.parse_args()
    files = sync_samples(Path(args.dest))
    for f in files:
        print(f"Fetched: {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
