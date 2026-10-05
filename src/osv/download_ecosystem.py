"""Download all OSV vulnerability JSONs for an ecosystem.

Defaults come from settings.ini (falling back to settings.default.ini):
OSV_ECOSYSTEM, OSV_JSON_PATH (JSONs go to <OSV_JSON_PATH>/<ecosystem>/) and
OSV_OUTPUT_PATH (where later analysis scripts write results).
Relative paths are resolved from the repository root.
"""
import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from config import read_config  # noqa: E402

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"


def load_settings() -> dict:
    ini = REPO_ROOT / "settings.ini"
    if not ini.exists():
        ini = REPO_ROOT / "settings.default.ini"
    return read_config(str(ini))


def resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p


def download(ecosystem: str, out_dir: Path) -> int:
    url = f"{BASE_URL}/{ecosystem}/all.zip"
    print(f"Downloading {url}")
    with urllib.request.urlopen(url) as resp:
        data = resp.read()

    print(f"Unzipping to {out_dir}...")
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            # Flatten and reject path traversal
            target = out_dir / Path(name).name
            if not name.endswith(".json"):
                continue
            target.write_bytes(zf.read(name))
            count += 1
    return count


def main():
    cfg = load_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", default=cfg.get("OSV_ECOSYSTEM") or "npm",
                        help="OSV ecosystem name (default: OSV_ECOSYSTEM)")
    parser.add_argument("--json-path", default=cfg.get("OSV_JSON_PATH") or "tmp/osv",
                        help="Base directory for JSONs (default: OSV_JSON_PATH)")
    parser.add_argument("--output-path", default=cfg.get("OSV_OUTPUT_PATH") or "output/osv",
                        help="Analysis output directory (default: OSV_OUTPUT_PATH)")
    args = parser.parse_args()

    out_dir = resolve(args.json_path) / args.ecosystem
    resolve(args.output_path).mkdir(parents=True, exist_ok=True)
    count = download(args.ecosystem, out_dir)
    print(f"Wrote {count} files to {out_dir}")


if __name__ == "__main__":
    main()
