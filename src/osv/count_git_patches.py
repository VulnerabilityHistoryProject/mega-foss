"""Count OSV vulnerabilities whose affected ranges include a GIT range with a fixed commit.

Reads <OSV_JSON_PATH>/<OSV_ECOSYSTEM>/*.json (see settings.ini).
"""
import argparse
import json

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

    json_dir = resolve(args.json_path) / args.ecosystem
    total = with_fix = 0
    files = list(json_dir.glob("*.json"))
    for path in tqdm(files, desc="Scanning", unit="file"):
        with open(path, encoding="utf-8") as f:
            vuln = json.load(f)
        total += 1
        if has_git_fix(vuln):
            with_fix += 1

    print(f"{with_fix} of {total} vulnerabilities in {json_dir} have a GIT fix commit")


if __name__ == "__main__":
    main()
