"""Compare a commit's similarity to an OSV description with and without the LLM summary.

Andy generated this script to compare commit embeddings with and without LLM summaries to see if it makes a difference.

Answer on Oct 21, 2026: with only one vulnerability as a data point, the cosine similarity was basically the same with and without the LLM summary.


Embeds the commit message + files + diff directly (no summary step) and prints its
cosine similarity to the vulnerability embedding, next to the similarity of the
summarized embedding that fix_tracer uses (read from the cache, or computed if absent).

Usage:
    python3 src/osv/compare_summary_embedding.py                       # every fix commit in the gold file
    python3 src/osv/compare_summary_embedding.py <vuln_id>             # that vuln's gold fix commit(s)
    python3 src/osv/compare_summary_embedding.py <vuln_id> <commit>    # a specific commit
Also accepts the fix_tracer options, plus --gold and --limit.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import numpy as np
from download_ecosystem import load_settings, resolve, zip_path_for
from fix_tracer import (Llm, build_parser, commit_details, commit_embedding, cosine, find_package_repo,
                        load_package_map, load_vuln, log, require_zip, resolve_sha, vuln_text)


def compare(args, llm, cache_dir, vuln_id, ref, repo_slug=None):
    vuln = load_vuln(zip_path_for(resolve(args.json_path), args.ecosystem), vuln_id)
    repo = args.repo_path
    if not repo:
        folder = repo_slug or find_package_repo(vuln, load_package_map(args.repo_list))
        if not folder:
            print(f"{vuln_id}: no repository found; pass --repo-path")
            return
        repo = resolve(args.repos_dir) / folder
    repo = Path(repo)
    sha = resolve_sha(repo, ref)
    if not sha:
        print(f"{vuln_id}: cannot resolve {ref} in {repo}")
        return

    log(f"{vuln_id}: embedding the vulnerability description")
    query = llm.embed(f"{vuln.get('summary', '')}\n{vuln_text(vuln)}", "query")

    c = commit_details(repo, sha)
    text = f"{c['message']}\n\nFiles: {', '.join(c['files'][:30])}\n\n{c['diff']}"
    log("embedding the commit without a summary")
    plain = cosine(query, llm.embed(text, "document"))

    log("getting the summarized embedding (cached if available)")
    s = commit_embedding(llm, repo, sha, cache_dir)
    summarized = cosine(query, np.array(s["embedding"], dtype=np.float32))

    print(f"\n{vuln_id}  {sha}  {c['message'].splitlines()[0] if c['message'] else ''}")
    print(f"  Without summary: {plain:.4f}")
    print(f"  With summary:    {summarized:.4f}  (summarize={llm.summarize})")
    print(f"  Difference:      {summarized - plain:+.4f}")
    if s.get("summary"):
        print(f"  Summary used: {s['summary']}")


def main():
    cfg = load_settings()
    p = build_parser(cfg)
    for action in p._actions:  # let vuln_id be omitted so the gold file is used
        if action.dest == "vuln_id":
            action.nargs, action.default, action.required = "?", None, False
    p.add_argument("sha", nargs="?", help="Commit SHA/ref (default: the gold file's fix commit)")
    p.add_argument("--gold", default=str(resolve(cfg.get("FIX_TRACER_GOLD_PATH") or "lists/fix_tracer_gold.csv")))
    p.add_argument("--limit", type=int, default=None, help="Only the first N gold rows")
    args = p.parse_args()

    require_zip(zip_path_for(resolve(args.json_path), args.ecosystem), args.ecosystem)
    cache_dir = resolve(args.cache_dir or str(resolve(args.output_path) / "tracer" / "cache"))
    llm = Llm(args.api_url, args.api_key, args.embed_model, args.chat_model,
              not args.no_summary, args.tokens_per_minute)

    if args.vuln_id and args.sha:
        compare(args, llm, cache_dir, args.vuln_id, args.sha)
        return

    with open(args.gold, newline="") as f:
        rows = list(csv.DictReader(f))
    if args.vuln_id:
        rows = [r for r in rows if r["vuln_id"] == args.vuln_id]
    for row in rows[:args.limit]:
        for ref in row["fix_commits"].replace(";", " ").split():
            compare(args, llm, cache_dir, row["vuln_id"], ref, row.get("repo") or None)


if __name__ == "__main__":
    main()
