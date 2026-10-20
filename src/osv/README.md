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
python src/osv/download_ecosystem.py --unzip               # also extract the JSONs
python src/osv/download_ecosystem.py --json-path some/dir --output-path out/dir
```

Requires `pymongo` (imported by `config.py`).

## fix_tracer.py

Finds the commit that fixed one OSV vulnerability (`python src/osv/fix_tracer.py <ID>`),
writing `<OSV_OUTPUT_PATH>/tracer/<ID>.json` and `.md` with a bulleted rationale.
`--blind` hides the OSV fix commits (test mode, output in `tracer_blind/`), and
`fix_tracer_eval.py` scores it against `lists/fix_tracer_gold.csv`
(`vuln_id,repo,fix_commits`). SLURM: `src/slurm/fix_tracer.slurm.sh`.

Besides `OSV_*` and `REPOSITORIES_PATH` (`REPOSITORY_LIST` csv matches OSV URLs to clones at `<REPOSITORIES_PATH>/<repo>`),
these `settings.ini` keys set the defaults (CLI flags override them):

| Key | Default | Purpose |
| --- | --- | --- |
| `FIX_TRACER_API_URL` | `https://api.genai.gccis.rit.edu/v1` | OpenAI-compatible API base URL |
| `FIX_TRACER_API_KEY` | _(empty)_ | API key; set it only in `settings.ini` (gitignored), never `settings.default.ini` |
| `FIX_TRACER_TOKENS_PER_MINUTE` | `10000` | Per-process token budget; the tracer sleeps to stay under it (`0` = off). With SLURM arrays the limit is shared, so divide it among concurrent tasks |
| `FIX_TRACER_EMBED_MODEL` | `embeddinggemma:latest` | Embedding model (list names with `GET <url>/models`) |
| `FIX_TRACER_CHAT_MODEL` | `qwen3:latest` | Model for summaries/rationales |
| `FIX_TRACER_SUMMARIZE` | `true` | LLM summary per candidate commit |
| `FIX_TRACER_DAYS_BEFORE` / `_AFTER` | `180` / `14` | Candidate window around the anchor date |
| `FIX_TRACER_MAX_CANDIDATES` | `200` | Cap on window commits embedded |
| `FIX_TRACER_TOP_K` | `3` | Commits reported |
| `FIX_TRACER_CACHE_PATH` | `<OSV_OUTPUT_PATH>/tracer/cache` | Embedding cache |
| `FIX_TRACER_GOLD_PATH` | `lists/fix_tracer_gold.csv` | Gold file for the eval harness |
