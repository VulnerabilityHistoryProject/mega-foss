"""Download the complete OSV dump (all ecosystems) to <OSV_JSON_PATH>/all.zip.

The file is ~3 GB, so the download streams to all.zip.part, prints a progress line
every --interval seconds, and resumes from the partial file if interrupted (re-run
the same command). all.zip appears only once the download is complete and verified.
Scripts should locate OSV data with download_ecosystem.find_zips(), which prefers
<OSV_JSON_PATH>/all.zip and falls back to <OSV_JSON_PATH>/<ecosystem>/all.zip.
"""
import argparse
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from download_ecosystem import BASE_URL, load_settings, resolve  # noqa: E402

CHUNK = 1 << 20


def download_all(out_dir: Path, interval: float, force: bool = False, timeout: int = 60) -> Path:
    url = f"{BASE_URL}/all.zip"
    final, part = out_dir / "all.zip", out_dir / "all.zip.part"
    out_dir.mkdir(parents=True, exist_ok=True)
    if final.exists() and not force:
        print(f"{final} exists; use --force to re-download")
        return final
    if force:
        part.unlink(missing_ok=True)

    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=timeout) as r:
        total = int(r.headers["Content-Length"])
        etag = r.headers.get("ETag", "")
    etag_file = out_dir / "all.zip.etag"
    if part.exists() and etag_file.exists() and etag_file.read_text() != etag:
        print("Remote file changed since the partial download; starting over")
        part.unlink()
    etag_file.write_text(etag)

    done = part.stat().st_size if part.exists() else 0
    while done < total:
        req = urllib.request.Request(url, headers={"Range": f"bytes={done}-"})
        start, start_done, last = time.monotonic(), done, time.monotonic()
        print(f"{'Resuming at' if done else 'Starting at'} {done / 1e6:.0f} MB of {total / 1e6:.0f} MB")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(part, "ab") as f:
                while chunk := resp.read(CHUNK):
                    f.write(chunk)
                    done += len(chunk)
                    if time.monotonic() - last >= interval:
                        last = time.monotonic()
                        rate = (done - start_done) / (last - start) / 1e6
                        eta = (total - done) / 1e6 / rate if rate else 0
                        print(f"  {done / 1e6:.0f}/{total / 1e6:.0f} MB ({100 * done / total:.1f}%) "
                              f"{rate:.1f} MB/s, ETA {eta / 60:.1f} min", flush=True)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            print(f"  interrupted: {e}; retrying in 10s", file=sys.stderr)
            time.sleep(10)
            done = part.stat().st_size if part.exists() else 0

    with zipfile.ZipFile(part) as zf:
        print(f"Verified zip with {len(zf.namelist())} entries")
    part.replace(final)
    etag_file.unlink(missing_ok=True)
    return final


def main():
    cfg = load_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-path", default=cfg.get("OSV_JSON_PATH") or "tmp/osv",
                        help="Base directory for OSV data (default: OSV_JSON_PATH)")
    parser.add_argument("--interval", type=float, default=30, help="Seconds between progress updates")
    parser.add_argument("--force", action="store_true", help="Re-download even if all.zip exists")
    args = parser.parse_args()
    print(f"Saved {download_all(resolve(args.json_path), args.interval, args.force)}")


if __name__ == "__main__":
    main()
