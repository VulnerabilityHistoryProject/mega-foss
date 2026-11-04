#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Optional

from prospector_lite import rank_commits


def process_single(
    cve_file: str,
    repo_path: str,
    tag_range: Optional[str] = None,
    max_candidates: int = 1000,
    top_k: int = 5,
    use_embeddings: bool = False,
    embedding_model: str = "all-MiniLM-L6-v2",
) -> Optional[dict]:
    try:
        return rank_commits(
            cve_input=cve_file,
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
            "cve_file": os.path.basename(cve_file),
            "repo_path": repo_path,
            "error": str(e),
        }


def run_batch_csv(
    csv_path: str,
    cve_dir: str,
    repos_dir: str,
    output_file: str,
    workers: int = 4,
    max_candidates: int = 1000,
    top_k: int = 5,
    use_embeddings: bool = False,
    embedding_model: str = "all-MiniLM-L6-v2",
):
    """
    Run in batch from a CSV file.
    Expected CSV columns (header optional):
    cve_id, repo_name, [optional tag_range]
    """
    tasks = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            cve_id = row[0].strip()
            # find cve file
            cve_file = os.path.join(cve_dir, f"{cve_id}.json")
            if not os.path.isfile(cve_file):
                # try without .json or direct filename
                cve_file = os.path.join(cve_dir, cve_id)
                if not os.path.isfile(cve_file):
                    continue

            repo_name = row[1].strip() if len(row) > 1 else ""
            repo_path = os.path.join(repos_dir, repo_name) if repo_name else ""
            if not os.path.isdir(repo_path):
                continue

            tag_range = row[2].strip() if len(row) > 2 else None
            tasks.append((cve_file, repo_path, tag_range))

    print(f"Loaded {len(tasks)} valid tasks from {csv_path}. Running with {workers} workers...")
    _execute_tasks(tasks, output_file, workers, max_candidates, top_k, use_embeddings, embedding_model)


def run_batch_dir(
    cve_dir: str,
    repos_dir: str,
    output_file: str,
    workers: int = 4,
    max_candidates: int = 1000,
    top_k: int = 5,
    use_embeddings: bool = False,
    embedding_model: str = "all-MiniLM-L6-v2",
):
    """
    Scan cve_dir for JSONs, match package name against repositories in repos_dir, and process.
    """
    tasks = []
    all_json_files = [
        os.path.join(cve_dir, f)
        for f in os.listdir(cve_dir)
        if f.endswith(".json")
    ]

    print(f"Scanning {len(all_json_files)} advisory files in {cve_dir}...")
    repo_dirs = {d.lower(): os.path.join(repos_dir, d) for d in os.listdir(repos_dir) if os.path.isdir(os.path.join(repos_dir, d))}

    for cve_path in all_json_files:
        try:
            with open(cve_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Find affected package or repo name
            pkg = ""
            for aff in data.get("affected", []):
                p = aff.get("package", {}).get("name")
                if p:
                    pkg = p
                    break
            # Match package to repo directory
            repo_path = None
            if pkg and pkg.lower() in repo_dirs:
                repo_path = repo_dirs[pkg.lower()]
            else:
                # Try matching by filename without extension
                base = os.path.splitext(os.path.basename(cve_path))[0].lower()
                if base in repo_dirs:
                    repo_path = repo_dirs[base]

            if repo_path and os.path.isdir(repo_path):
                tasks.append((cve_path, repo_path, None))
        except Exception:
            continue

    print(f"Matched {len(tasks)} advisories to local repositories. Running with {workers} workers...")
    _execute_tasks(tasks, output_file, workers, max_candidates, top_k, use_embeddings, embedding_model)


def _execute_tasks(tasks, output_file, workers, max_candidates, top_k, use_embeddings, embedding_model):
    processed = 0
    errors = 0

    with open(output_file, "w", encoding="utf-8") as out_f:
        if workers > 1:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                future_to_cve = {
                    executor.submit(process_single, t[0], t[1], t[2], max_candidates, top_k, use_embeddings, embedding_model): t
                    for t in tasks
                }
                for future in as_completed(future_to_cve):
                    res = future.result()
                    if res:
                        if "error" in res:
                            errors += 1
                        out_f.write(json.dumps(res) + "\n")
                        out_f.flush()
                        processed += 1
                        if processed % 100 == 0 or processed == len(tasks):
                            print(f"Progress: {processed}/{len(tasks)} (errors: {errors})")
        else:
            for t in tasks:
                res = process_single(t[0], t[1], t[2], max_candidates, top_k, use_embeddings, embedding_model)
                if res:
                    if "error" in res:
                        errors += 1
                    out_f.write(json.dumps(res) + "\n")
                    out_f.flush()
                    processed += 1
                    if processed % 100 == 0 or processed == len(tasks):
                        print(f"Progress: {processed}/{len(tasks)} (errors: {errors})")

    print(f"Done! Results written to {output_file} (Processed: {processed}, Errors: {errors})")

    with open(output_file, "w", encoding="utf-8") as out_f:
        if workers > 1:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                future_to_cve = {
                    executor.submit(process_single, t[0], t[1], t[2], max_candidates, top_k): t
                    for t in tasks
                }
                for future in as_completed(future_to_cve):
                    res = future.result()
                    if res:
                        if "error" in res:
                            errors += 1
                        out_f.write(json.dumps(res) + "\n")
                        out_f.flush()
                        processed += 1
                        if processed % 100 == 0 or processed == len(tasks):
                            print(f"Progress: {processed}/{len(tasks)} (errors: {errors})")
        else:
            for t in tasks:
                res = process_single(t[0], t[1], t[2], max_candidates, top_k)
                if res:
                    if "error" in res:
                        errors += 1
                    out_f.write(json.dumps(res) + "\n")
                    out_f.flush()
                    processed += 1
                    if processed % 100 == 0 or processed == len(tasks):
                        print(f"Progress: {processed}/{len(tasks)} (errors: {errors})")

    print(f"Done! Results written to {output_file} (Processed: {processed}, Errors: {errors})")


def main():
    parser = argparse.ArgumentParser(description="Prospector-Lite: Fast, offline fixing commit ranker")

    parser.add_argument("vuln_id", nargs="?", default=None, help="Vulnerability ID (e.g. GHSA-xxx, CVE-xxx)")
    parser.add_argument("--cve-file", help="Path to local OSV/CVE JSON file")
    parser.add_argument("--repo-path", help="Path to local cloned git repository")
    parser.add_argument("--tag-range", "--tags", dest="tag_range", default=None, help="Version/tag interval (e.g. v1.0.0:v1.0.1)")

    # Batch arguments
    parser.add_argument("--batch-csv", help="Path to batch CSV file (cve_id, repo_name, [tag_range])")
    parser.add_argument("--cve-dir", help="Directory containing CVE/OSV JSON files for batch run")
    parser.add_argument("--repos-dir", help="Directory containing cloned git repositories for batch run")
    parser.add_argument("--output", "-o", default="results.jsonl", help="Output file for batch results (default: results.jsonl)")
    parser.add_argument("--workers", "-w", type=int, default=os.cpu_count() or 4, help="Number of worker processes for batch mode")
    parser.add_argument("--max-candidates", type=int, default=1000, help="Max candidates per vulnerability (default: 1000)")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top candidates to report (default: 5)")

    # Embedding arguments
    parser.add_argument("--use-embeddings", action="store_true", help="Enable model embeddings to boost fix candidate classification accuracy")
    parser.add_argument("--embedding-model", default="all-MiniLM-L6-v2", help="SentenceTransformer model name or path to local model directory (default: all-MiniLM-L6-v2)")

    args = parser.parse_args()

    # Batch mode via CSV
    if args.batch_csv:
        if not args.cve_dir or not args.repos_dir:
            print("Error: --batch-csv requires both --cve-dir and --repos-dir")
            sys.exit(1)
        run_batch_csv(
            args.batch_csv,
            args.cve_dir,
            args.repos_dir,
            args.output,
            workers=args.workers,
            max_candidates=args.max_candidates,
            top_k=args.top_k,
            use_embeddings=args.use_embeddings,
            embedding_model=args.embedding_model,
        )
        return

    # Batch mode via scanning directory
    if args.cve_dir and args.repos_dir and not args.cve_file:
        run_batch_dir(
            args.cve_dir,
            args.repos_dir,
            args.output,
            workers=args.workers,
            max_candidates=args.max_candidates,
            top_k=args.top_k,
            use_embeddings=args.use_embeddings,
            embedding_model=args.embedding_model,
        )
        return

    # Single run mode
    if not args.cve_file or not args.repo_path:
        parser.print_help()
        sys.exit(1)

    print(f"Evaluating {args.vuln_id or os.path.basename(args.cve_file)} against {args.repo_path}...")
    result = rank_commits(
        cve_input=args.cve_file,
        repo_path=args.repo_path,
        tag_range=args.tag_range,
        max_candidates=args.max_candidates,
        top_k=args.top_k,
        use_embeddings=args.use_embeddings,
        embedding_model=args.embedding_model,
        show_progress=True,
    )

    print(f"\nTotal candidate commits found: {result['total_candidates']}")
    print(f"Top fix commit: {result['top_commit']} (Score: {result['top_score']})\n")

    print(f"{'#':<3} {'Score':<7} {'SHA':<10} {'Message':<50} {'Rules Matched'}")
    print("-" * 100)
    for i, c in enumerate(result["ranked_commits"], 1):
        rules_str = ", ".join([r["rule"] for r in c["matched_rules"]])
        msg = (c["message"][:47] + "...") if len(c["message"]) > 47 else c["message"]
        print(f"{i:<3} {c['score']:<7} {c['short_id']:<10} {msg:<50} {rules_str}")

    if args.output and args.output != "results.jsonl":
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"\nSaved detailed JSON to {args.output}")


if __name__ == "__main__":
    main()
