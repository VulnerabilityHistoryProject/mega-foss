"""Test mode for fix_tracer: score it against vulnerabilities with known fix commits.

Gold file (CSV with header), default lists/fix_tracer_gold.csv:
    vuln_id,repo,fix_commits
    GHSA-xxxx-xxxx-xxxx,owner/name,abc1234 def5678

  repo        owner/name under REPOSITORIES_PATH, or an absolute path; blank = infer from OSV.
  fix_commits space-separated SHAs (prefixes ok); any one in the ranking counts as a hit.

Each vulnerability is traced with the answer hidden (--blind) and results go to
<OSV_OUTPUT_PATH>/tracer_blind/. Reports Top-k accuracy and the rank of each expected commit, and writes eval_summary.json alongside.

    python3 src/osv/fix_tracer_eval.py                       # whole gold file
    python3 src/osv/fix_tracer_eval.py --limit 5 --no-summary # quick smoke test
    python3 src/osv/fix_tracer_eval.py --ecosystem PyPI --gold my_gold.csv
Extra tracer options (--chat-model, --days-before, ...) are accepted.
"""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from download_ecosystem import load_settings, resolve  # noqa: E402
from fix_tracer import blind, build_parser, load_vuln, log, require_zip, trace  # noqa: E402


def rank_of(ranked: list[dict], expected: list[str]) -> int | None:
    for i, c in enumerate(ranked, 1):
        if any(c["sha"].startswith(e) or e.startswith(c["sha"]) for e in expected):
            return i
    return None


def main():
    cfg = load_settings()
    parser = build_parser(cfg)
    parser.description = __doc__
    parser.set_defaults(vuln_id=None)
    parser.add_argument("--gold", default=str(resolve(cfg.get("FIX_TRACER_GOLD_PATH") or "lists/fix_tracer_gold.csv")))
    parser.add_argument("--limit", type=int, help="Only evaluate the first N rows")
    args, _ = parser.parse_known_args(["_"] + sys.argv[1:])
    args.blind = True
    args.top_k = max(args.top_k, 3)

    out_dir = resolve(args.output_path) / "tracer_blind"
    out_dir.mkdir(parents=True, exist_ok=True)
    args.cache_dir = args.cache_dir or str(resolve(args.output_path) / "tracer" / "cache")
    zip_path = resolve(args.json_path) / args.ecosystem / "all.zip"
    require_zip(zip_path, args.ecosystem)

    with open(args.gold, newline="") as f:
        rows = list(csv.DictReader(f))[:args.limit]

    results = []
    for n, row in enumerate(rows, 1):
        log(f"=== [{n}/{len(rows)}] {row['vuln_id'].strip()} ===")
        vuln_id, expected = row["vuln_id"].strip(), row["fix_commits"].split()
        args.repo_path = None
        repo = (row.get("repo") or "").strip()
        if repo:
            args.repo_path = repo if Path(repo).is_absolute() else str(resolve(args.repos_dir) / repo)
        try:
            res = trace(args, blind(load_vuln(zip_path, vuln_id)))
        except (Exception, SystemExit) as e:
            res = {"id": vuln_id, "status": f"error: {e}", "candidates": []}
        (out_dir / f"{vuln_id}.json").write_text(json.dumps(res, indent=2))
        rank = rank_of(res["candidates"], expected)
        results.append({"id": vuln_id, "status": res["status"], "rank": rank,
                        "confidence": res.get("confidence")})
        print(f"{vuln_id}: {res['status']} rank={rank}", flush=True)
        if res["status"] != "ok":
            log(f"  skipped: {res['status']}")

    n = len(results)
    summary = {"total": n, "ecosystem": args.ecosystem, "results": results}
    for k in (1, 3, args.top_k):
        summary[f"top{k}"] = sum(1 for r in results if r["rank"] and r["rank"] <= k)
    summary["unresolved"] = sum(1 for r in results if r["status"] != "ok")
    (out_dir / "eval_summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\nEvaluated {n} (unresolved: {summary['unresolved']})")
    for k in sorted({1, 3, args.top_k}):
        print(f"Top-{k}: {summary[f'top{k}']}/{n} = {summary[f'top{k}'] / n:.0%}" if n else f"Top-{k}: n/a")


if __name__ == "__main__":
    main()
