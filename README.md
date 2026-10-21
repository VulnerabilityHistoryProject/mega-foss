# MegaFoss 
MegaFoss is a project dedicatd to collecting and analyzing vulnerability data from open source software to better understand and improve software security. It provides tools and datasets to map, track and study vulnerabilities across popular projects

# Setup Guide
## Required Programs
- MongoDB Compass (https://www.mongodb.com/try/download/compass) - Gui version - Windows / Linux / Mac
- MongoDB Shell (https://www.mongodb.com/try/download/shell) - Windows / Linux / Mac
- MongoDB Tools (https://www.mongodb.com/try/download/database-tools) - Windows / Linux / Mac
- Python 3.11.3 or higher

## Install Python dependencies
Dependencies are declared in ```pyproject.toml```. Use the following command from the root folder to install them (venv is recomended)

```
pip install .
```

## Create mongo database
### MongoDB Shell
Run the following command in your terminal to ensure the MongoDB database exists and the main collection cve is created:

```
mongosh
```

Then in the Mongo shell:

```
use megafoss
db.createCollection("cves")
```

### MongoDB Compass
Open MongoDB compass and connect to your local MongoDB instance using:

```
Hostname: localhost
Port: 27017
```

Once connected you can explore the databse and the collection

## Create settings.ini
To configure the project copy the template file ```settings.default.ini``` from the root folder and rename it to settings.ini. Then update the values according to your environment

The file should look like this:

```
DATABASE="megafoss"
HOST="127.0.0.1"
PORT="27017"
REPOSITORIES_PATH="D:/path/to/repos/folder"
REPOSITORY_LIST="C:/path/to/repos/lists/repositories.csv"
NVDCVE_PATH="E:/path/to/nvdcve/files"
OSV_ECOSYSTEM="npm"
OSV_JSON_PATH="tmp/osv"
OSV_OUTPUT_PATH="output/osv"
```

## Obtain and import CVE data
First clone the nvdcve github repository: 

```
https://github.com/olbat/nvdcve
```

Then run the provided bash script from the project root to import the CVE data:

```
bulk_import_nvdcve.sh
```

## Clone repositories
Create a folder named ```mega-foss-repositories``` as a sibling to the project folder. The ```repositories.csv``` contains a list of repositories, one per line as ```repo,url``` (header row, then ```owner/name,clone-url```), that would be used after clonning them to match with the different NVDCVEs that are inside the database

To clone all the resporitories from the ```repositories.csv``` run the following command:

```
bash bulk_clone_repositories.sh
```

# Scripts
## Match repositories with CVEs
The script with name ```mg_repos_match_cve ``` will match the CVEs inside the database with the different repos that we have inside ```mega-foss-repositories```

To run the script, which is located in ```src/cve```, use the following command:

```
python -m src.cve.mg_repos_match_cve
```

## OSV vulnerabilities

### Download an ecosystem

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
python3 src/osv/download_ecosystem.py                       # use settings
python3 src/osv/download_ecosystem.py --ecosystem PyPI      # override ecosystem
python3 src/osv/download_ecosystem.py --unzip               # also extract the JSONs
python3 src/osv/download_ecosystem.py --json-path some/dir --output-path out/dir
```

Requires `pymongo` (imported by `config.py`).

### Trace OSV vulnerabilities to their fix commits

Finds the commit that fixed one OSV vulnerability (`python src/osv/fix_tracer.py <ID>`),
writing `<OSV_OUTPUT_PATH>/tracer/<ID>.json` and `.md` with a bulleted rationale.
Candidate commits come from the OSV record's GIT ranges and commit links, plus the commits
in a date window. The window starts 30 days (`FIX_TRACER_TAG_BUFFER_DAYS`) before the date of the newest git tag that matches an affected
version (distro versions like `6:9.20-0ubuntu0.14.04.1` are reduced to `9.20`; if no tag matches
exactly, the closest tags sharing a major.minor are used) and ends at a later fixed-version tag,
else 14 days after the publication date. Without a matching tag it falls back to a window around
the publication date. Tag dates are read once per repo and cached in `<cache>/tags/`; use
`--refresh-tags` to rebuild them. Embedding similarity dominates the ranking; the date counts for
very little, since fixes often land well before the OSV date.
`--blind` hides the OSV fix commits (test mode, output in `tracer_blind/`), and
`fix_tracer_eval.py` scores it against `lists/fix_tracer_gold.csv`
(`vuln_id,repo,fix_commits`). SLURM: `src/slurm/fix_tracer.slurm.sh`.

Besides `OSV_*` and `REPOSITORIES_PATH` (clones live at `<REPOSITORIES_PATH>/<repo>`),
these `settings.ini` keys set the defaults (CLI flags override them):

| Key | Default | Purpose |
| --- | --- | --- |
| `FIX_TRACER_API_URL` | `https://api.genai.gccis.rit.edu/v1` | OpenAI-compatible API base URL |
| `FIX_TRACER_API_KEY` | _(empty)_ | API key; set it only in `settings.ini` (gitignored), never `settings.default.ini` |
| `FIX_TRACER_TOKENS_PER_MINUTE` | `10000` | Per-process token budget; the tracer sleeps to stay under it (`0` = off). With SLURM arrays the limit is shared, so divide it among concurrent tasks |
| `FIX_TRACER_EMBED_MODEL` | `embeddinggemma:latest` | Embedding model (list names with `GET <url>/models`) |
| `FIX_TRACER_CHAT_MODEL` | `qwen3:latest` | Model for summaries/rationales |
| `FIX_TRACER_SUMMARIZE` | `true` | LLM summary per candidate commit |
| `FIX_TRACER_TAG_BUFFER_DAYS` | `30` | Days before the newest affected tag to start the window (fixes land before releases) |
| `FIX_TRACER_DAYS_BEFORE` / `_AFTER` | `180` / `14` | Days before/after the publication date; `_BEFORE` only applies when no affected-version tag matches |
| `FIX_TRACER_MAX_CANDIDATES` | `200` | Cap on window commits embedded |
| `FIX_TRACER_TOP_K` | `3` | Commits reported |
| `FIX_TRACER_CACHE_PATH` | `<OSV_OUTPUT_PATH>/tracer/cache` | Embedding cache |
| `FIX_TRACER_PACKAGE_MAP` | `lists/package_repos.csv` | CSV `ecosystem,package,repo` mapping an OSV package to its clone folder (no URL parsing; unmapped packages report `no_repo_found`) |
| `FIX_TRACER_GOLD_PATH` | `lists/fix_tracer_gold.csv` | Gold file for the eval harness |

#### Connecting to an AI backend

`fix_tracer.py` talks to any OpenAI-compatible API (`/embeddings` and `/chat/completions`),
so switching backends only means changing `settings.ini`. Embeddings are cached per API URL
and model, so each backend keeps its own cache.

**RIT AI (`api.genai.gccis.rit.edu`)**

```ini
FIX_TRACER_API_URL="https://api.genai.gccis.rit.edu/v1"
FIX_TRACER_API_KEY="<your key>"
FIX_TRACER_TOKENS_PER_MINUTE="10000"
FIX_TRACER_EMBED_MODEL="embeddinggemma:latest"
FIX_TRACER_CHAT_MODEL="qwen3:latest"
```

- `settings.ini` is gitignored; keep the key there and never in `settings.default.ini`.
- List the models your key can use: `curl -H "Authorization: Bearer $KEY" https://api.genai.gccis.rit.edu/v1/models`
- Keep `FIX_TRACER_TOKENS_PER_MINUTE` at your account's limit so the tracer waits instead of getting HTTP 429s.
  The budget is per process, so for parallel SLURM tasks divide it by the number of concurrent tasks.

**Local Ollama**

1. Install Ollama (https://ollama.com/download) and make sure it is running (`ollama serve`, or the desktop app).
2. Pull the models:
   ```
   ollama pull embeddinggemma
   ollama pull qwen3
   ```
3. Point the tracer at it in `settings.ini`:
   ```ini
   FIX_TRACER_API_URL="http://localhost:11434/v1"
   FIX_TRACER_API_KEY=""
   FIX_TRACER_TOKENS_PER_MINUTE="0"
   FIX_TRACER_EMBED_MODEL="embeddinggemma:latest"
   FIX_TRACER_CHAT_MODEL="qwen3:latest"
   ```
   No API key is needed for `localhost`, and `0` turns the token throttle off.
4. Check it: `curl http://localhost:11434/v1/models` should list the pulled models.

Model names must match `ollama list` exactly (including `:latest`). For a faster local run, use
a smaller chat model or skip summaries (`FIX_TRACER_SUMMARIZE="false"` or `--no-summary`).
Any flag can override a setting for one run, e.g.
`python src/osv/fix_tracer.py <ID> --api-url http://localhost:11434/v1 --tokens-per-minute 0`.

# Outputs
All outputs from the project would be inside the root folder ```output```

# Historic CVEs
```
python3 historic_population.py
