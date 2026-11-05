#!/usr/bin/env python3
"""
SLURM Job Array Batch Runner for Prospector-Lite.

Reads a master CSV file, automatically determines the current SLURM array
task chunk, runs candidate commit ranking across worker processes, and
writes JSONL outputs per task.
"""

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from prospector_lite import rank_commits


def get_slurm_array_info() -> Tuple[int, int]:
    """
    Returns (task_id, total_tasks) based on SLURM environment variables.
    Defaults to (0, 1) if not running under a SLURM array.
    """
    task_id = int(os.environ.get("SLURM_ARRAY_TASK_ID", 0))

    if "SLURM_ARRAY_TASK_COUNT" in os.environ:
        total_tasks = int(os.environ["SLURM_ARRAY_TASK_COUNT"])
    elif "SLURM_ARRAY_TASK_MAX" in os.environ and "SLURM_ARRAY_TASK_MIN" in os.environ:
        min_id = int(os.environ["SLURM_ARRAY_TASK_MIN"])
        max_id = int(os.environ["SLURM_ARRAY_TASK_MAX"])
        step = int(os.environ.get("SLURM_ARRAY_TASK_STEP", 1))
        total_tasks = ((max_id - min_id) // step) + 1
    else:
        total_tasks = 1

    return task_id, max(1, total_tasks)


def process_item(
    cve_path: str,
    repo_path: str,
    tag_range: Optional[str] = None,
    top_k: int = 5,
    max_candidates: int = 1000,
    use_embeddings: bool = False,
    embedding_model: str = "all-MiniLM-L6-v2",
) -> Optional[dict]:
    try:
        return rank_commits(
            cve_input=cve_path,
            repo_path=repo_path,
            tag_range=tag_range,
            max_candidates=max_candidates,
            top_k=top_k,
            fetch_diff=True,
            use_embeddings=use_embeddings,
            embedding_model=embedding_model,
        )
    except Exception as e:
        return {
            "cve": os.path.basename(cve_path),
            "repo": os.path.basename(repo_path),
            "error": str(e),
        }


def parse_csv_row(row: list, headers: Optional[List[str]]) -> Tuple[str, str, Optional[str]]:
    """
    Extracts (cve_identifier_or_json, repo_folder, optional_tag_range).
    Supports either named header dict or positional fallback:
      - 3+ cols: [osv_id, json_filename, owner_repo, ...]
      - 2 cols:  [osv_id_or_json, owner_repo]
    """
    row_stripped = [col.strip() for col in row]

    if headers:
        header_map = {name.lower().replace("-", "_").replace(" ", "_"): idx for idx, name in enumerate(headers)}
        # Look for explicit header names
        cve_col = header_map.get("osv_json_filename") or header_map.get("osv_json") or header_map.get("osv_id") or header_map.get("vuln_id") or 0
        repo_col = header_map.get("owner_repo") or header_map.get("repo") or header_map.get("repo_name") or header_map.get("repository") or 1
        tag_col = header_map.get("tag_range") or header_map.get("tags") or None

        cve_val = row_stripped[cve_col] if isinstance(cve_col, int) and cve_col < len(row_stripped) else row_stripped[0]
        repo_val = row_stripped[repo_col] if isinstance(repo_col, int) and repo_col < len(row_stripped) else row_stripped[1]
        tag_val = row_stripped[tag_col] if (tag_col is not None and tag_col < len(row_stripped)) else None
        return cve_val, repo_val, tag_val

    # Positional fallback
    if len(row_stripped) >= 3 and row_stripped[1].endswith(".json"):
        # Format: osv_id, osv_json_filename, owner_repo
        cve_val = row_stripped[1]
        repo_val = row_stripped[2]
        tag_val = row_stripped[3] if len(row_stripped) > 3 else None
    else:
        # Format: osv_id, owner_repo, [tag_range]
        cve_val = row_stripped[0]
        repo_val = row_stripped[1]
        tag_val = row_stripped[2] if len(row_stripped) > 2 else None

    return cve_val, repo_val, tag_val


def main():
    parser = argparse.ArgumentParser(description="Run Prospector-Lite across a SLURM job array")
    parser.add_argument("--csv", required=True, help="Path to master mapping CSV")
    parser.add_argument("--cve-dir", required=True, help="Directory containing OSV/CVE JSON files")
    parser.add_argument("--repos-dir", required=True, help="Directory containing cloned git repos (owner_repo)")
    parser.add_argument("--workers", type=int, default=int(os.environ.get("SLURM_CPUS_PER_TASK", 4)), help="Number of worker processes")
    parser.add_argument("--output-dir", default="output", help="Directory for output files")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top candidates to report (default: 5)")
    parser.add_argument("--max-candidates", type=int, default=1000, help="Max commit candidates per advisory")
    parser.add_argument("--use-embeddings", action="store_true", help="Enable semantic embedding boost")
    parser.add_argument("--embedding-model", default="all-MiniLM-L6-v2", help="Embedding model name or local path")
    args = parser.parse_args()

    task_id, total_tasks = get_slurm_array_info()
    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Read all rows from master CSV
    all_rows = []
    headers = None
    with open(args.csv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or not any(field.strip() for field in row):
                continue
            if row[0].strip().startswith("#"):
                continue
            if headers is None and ("osv" in row[0].lower() or "id" in row[0].lower() or "repo" in row[0].lower()):
                headers = [h.strip() for h in row]
                continue
            all_rows.append(row)

    # 2. Slice items in Python for this specific array task
    my_rows = [row for i, row in enumerate(all_rows) if (i % total_tasks) == task_id]
    print(f"[Task {task_id}/{total_tasks}] Assigned {len(my_rows)} of {len(all_rows)} total records.")

    # 3. Resolve paths
    tasks = []
    skipped = 0
    for row in my_rows:
        cve_ref, repo_name, tag_range = parse_csv_row(row, headers)

        # Resolve CVE file
        cve_file = cve_ref if cve_ref.endswith(".json") else f"{cve_ref}.json"
        cve_path = os.path.join(args.cve_dir, cve_file)
        if not os.path.isfile(cve_path):
            # check direct filename
            cve_path = os.path.join(args.cve_dir, cve_ref)
            if not os.path.isfile(cve_path):
                skipped += 1
                continue

        # Resolve repository path
        repo_path = os.path.join(args.repos_dir, repo_name)
        if not os.path.isdir(repo_path):
            skipped += 1
            continue

        tasks.append((cve_path, repo_path, tag_range))

    print(f"[Task {task_id}] Ready to process {len(tasks)} valid tasks ({skipped} skipped/missing).")

    job_id = os.environ.get("SLURM_ARRAY_JOB_ID", os.environ.get("SLURM_JOB_ID", "local"))
    out_file = os.path.join(args.output_dir, f"results_{job_id}_{task_id}.jsonl")

    # 4. Execute with pool
    processed = 0
    errors = 0
    with open(out_file, "w", encoding="utf-8") as out_f:
        if args.workers > 1 and len(tasks) > 1:
            with ProcessPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(
                        process_item,
                        t[0],
                        t[1],
                        t[2],
                        args.top_k,
                        args.max_candidates,
                        args.use_embeddings,
                        args.embedding_model,
                    ): t
                    for t in tasks
                }
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        if "error" in res:
                            errors += 1
                        out_f.write(json.dumps(res) + "\n")
                        out_f.flush()
                    processed += 1
                    if processed % 25 == 0 or processed == len(tasks):
                        print(f"[Task {task_id}] Progress: {processed}/{len(tasks)} (errors: {errors})")
        else:
            for t in tasks:
                res = process_item(
                    t[0],
                    t[1],
                    t[2],
                    args.top_k,
                    args.max_candidates,
                    args.use_embeddings,
                    args.embedding_model,
                )
                if res:
                    if "error" in res:
                        errors += 1
                    out_f.write(json.dumps(res) + "\n")
                    out_f.flush()
                processed += 1
                if processed % 25 == 0 or processed == len(tasks):
                    print(f"[Task {task_id}] Progress: {processed}/{len(tasks)} (errors: {errors})")

    print(f"[Task {task_id}] Complete! Results -> {out_file} (Processed: {processed}, Errors: {errors})")


if __name__ == "__main__":
    main()
