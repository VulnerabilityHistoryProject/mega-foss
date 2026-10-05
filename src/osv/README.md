# OSV

## download_ecosystem.py

Downloads every vulnerability JSON for an ecosystem from the OSV bulk export
(`https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`)
and extracts them to `<OSV_JSON_PATH>/<ecosystem>/` (default `tmp/osv/npm/`).

Defaults are read from `settings.ini` (falling back to `settings.default.ini`):

| Key | Default | Purpose |
| --- | --- | --- |
| `OSV_ECOSYSTEM` | `npm` | OSV ecosystem to download |
| `OSV_JSON_PATH` | `tmp/osv` | Base folder for downloaded JSONs |
| `OSV_OUTPUT_PATH` | `output/osv` | Output folder for later analysis scripts (created by the downloader) |

Relative paths resolve from the repository root.

```
python src/osv/download_ecosystem.py                       # use settings
python src/osv/download_ecosystem.py --ecosystem PyPI      # override ecosystem
python src/osv/download_ecosystem.py --json-path some/dir --output-path out/dir
```

Requires `pymongo` (imported by `config.py`).
