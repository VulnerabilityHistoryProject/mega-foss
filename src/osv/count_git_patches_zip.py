"""Like count_git_patches.py, but reads the JSONs straight from all.zip.

Reads <OSV_JSON_PATH>/<OSV_ECOSYSTEM>/all.zip (see settings.ini).
"""
import argparse
import zipfile

import orjson
from tqdm import tqdm

from download_ecosystem import load_settings, resolve

def has_git_fix(vuln: dict) -> bool:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            if any("fixed" in event for event in rng.get("events", [])):
                return True
    return False


def main():
    cfg = load_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", default=cfg.get("OSV_ECOSYSTEM") or "npm")
    parser.add_argument("--json-path", default=cfg.get("OSV_JSON_PATH") or "tmp/osv")
    args = parser.parse_args()

    zip_path = resolve(args.json_path) / args.ecosystem / "all.zip"
    total = with_fix = 0
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        for name in tqdm(names, desc="Scanning", unit="file"):
            vuln = orjson.loads(zf.read(name))
            total += 1
            if has_git_fix(vuln):
                with_fix += 1

    print(f"{with_fix} of {total} vulnerabilities in {zip_path} have a GIT fix commit")


if __name__ == "__main__":
    main()
