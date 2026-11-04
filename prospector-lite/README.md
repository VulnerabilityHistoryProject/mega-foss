# Prospector-Lite

A lightweight version of project-kb's prospector. This version works offline, OSV, and uses embedding support
Link to the original project: [Project KB](https://sap.github.io/project-kb/)

---

## Directory Structure
```
prospector-lite/
├── advisory.py         # Parses OSV JSON advisories (metadata, files, keywords, refs)
├── git_ops.py          # Fast local git operations (git log, tag ranges, diff hunks)
├── rules.py            # Heuristic ranking rules (Phase 1 scores & weights)
├── ranker.py           # Evaluates rules and sorts candidate commits
├── prospector_lite.py  # Core Python API (rank_commits)
├── cli.py              # Command-line & high-throughput batch runner
└── requirements.txt    # Minimal dependencies
```

---

## Usage

### 1. Single Vulnerability Test
```bash
python cli.py GHSA-xxxx \
    --cve-file /path/to/advisories/GHSA-xxxx.json \
    --repo-path /path/to/repos/my-repo \
    --tags v1.0.0:v1.0.1
```

### 2. High-Throughput Batch Run (e.g., on SLURM Compute Node)
Run in parallel across 16 CPU cores:

```bash
python cli.py \
    --cve-dir /path/to/cve_jsons/ \
    --repos-dir /path/to/repos/ \
    --output ranked_results.jsonl \
    --workers 16
```

Or using an input CSV list (`cve_id, repo_name, [tag_range]`):
```bash
python cli.py \
    --batch-csv dataset.csv \
    --cve-dir /path/to/cve_jsons/ \
    --repos-dir /path/to/repos/ \
    --output ranked_results.jsonl \
    --workers 16
```

### 3. As a Python Library
```python
from prospector_lite import rank_commits

results = rank_commits(
    cve_input="/path/to/GHSA-xxxx.json", # or pass a dict
    repo_path="/path/to/cloned/repo",
    tag_range="v1.0.0:v1.0.1",          # optional tag range
    top_k=5,
    use_embeddings=True,                # optional semantic embedding boost
)

print(results["top_commit"], results["top_score"])
for commit in results["ranked_commits"]:
    print(commit["short_id"], commit["score"], commit["matched_rules"])
```

### 4. Semantic Embeddings for Silent Fixes (Optional)
To boost accuracy on ambiguous or "silent" fixes (where commit messages don't mention CVE IDs), enable model embeddings:

```bash
# Requires sentence-transformers: pip install sentence-transformers
python cli.py GHSA-xxxx \
    --cve-file /path/to/advisories/GHSA-xxxx.json \
    --repo-path /path/to/repos/my-repo \
    --tags v1.0.0:v1.0.1 \
    --use-embeddings \
    --embedding-model all-MiniLM-L6-v2
```

You can also point `--embedding-model` to a pre-downloaded model directory:
```bash
python cli.py ... --use-embeddings --embedding-model /scratch/$USER/models/all-MiniLM-L6-v2
```

---

## Output Format (`results.jsonl`)
Each line is a JSON object:
```json
{
  "vuln_id": "GHSA-xxxx",
  "aliases": ["CVE-2021-xxxx"],
  "package": "crate_name",
  "repo_path": "/path/to/repo",
  "tag_range": "v1.0.0:v1.0.1",
  "total_candidates": 45,
  "top_commit": "4b825dc6f92...",
  "top_score": 72,
  "ranked_commits": [
    {
      "commit_id": "4b825dc6f92...",
      "short_id": "4b825dc6",
      "score": 72,
      "timestamp": 1623912345,
      "message": "fix: prevent buffer overflow (#12)",
      "changed_files": ["src/parser.rs"],
      "matched_rules": [
        {"rule": "COMMIT_IN_REFERENCE", "weight": 64, "reason": "..."},
        {"rule": "CHANGES_RELEVANT_FILES", "weight": 8, "reason": "..."}
      ]
    }
  ]
}
```
