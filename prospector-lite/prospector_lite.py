import os
from typing import Any, Dict, List, Optional, Union

from advisory import Advisory
from git_ops import CandidateCommit, GitRepo
from ranker import rank_candidates


def rank_commits(
    cve_input: Union[str, dict],
    repo_path: str,
    tag_range: Optional[str] = None,
    since: Optional[int] = None,
    until: Optional[int] = None,
    max_candidates: int = 2000,
    top_k: Optional[int] = 10,
    fetch_diff: bool = True,
    use_embeddings: bool = False,
    embedding_model: str = "all-MiniLM-L6-v2",
    show_progress: bool = False,
) -> Dict[str, Any]:
    """
    Main function to rank candidate fixing commits for a vulnerability.

    Args:
        cve_input: Path to a local OSV JSON file or a dictionary containing OSV data.
        repo_path: Path to the local cloned git repository.
        tag_range: Tag/version interval (e.g. 'v1.0.0:v1.0.1' or 'v1.0.0..v1.0.1').
        since: Optional epoch timestamp to start search.
        until: Optional epoch timestamp to end search.
        max_candidates: Maximum number of commits to retrieve from git log.
        top_k: Number of top candidate commits to return in the output (None = all).
        fetch_diff: Whether to fetch diffs for candidate commits.

    Returns:
        Dictionary with vulnerability metadata, total candidates evaluated, and ranked commits.
    """
    # 1. Load advisory
    if isinstance(cve_input, str):
        if not os.path.isfile(cve_input):
            raise FileNotFoundError(f"Advisory file not found: {cve_input}")
        advisory = Advisory.from_file(cve_input)
    elif isinstance(cve_input, dict):
        advisory = Advisory(cve_input)
    else:
        raise TypeError("cve_input must be a file path string or a dict")

    # 2. Open Git repository
    repo = GitRepo(repo_path)

    # 3. If tag_range is not provided, try to infer from advisory timestamps
    if not tag_range and not since and not until and advisory.published_timestamp:
        since = advisory.published_timestamp - (180 * 86400)
        until = advisory.published_timestamp + (60 * 86400)

    # 4. Extract candidate commits (fast metadata only)
    candidates = repo.get_commits(
        tag_range=tag_range,
        since=since,
        until=until,
        max_candidates=max_candidates,
        fetch_diff=False,
    )

    # 4b. Also include any commits explicitly referenced in advisory if not already present
    existing_ids = {c.commit_id.lower() for c in candidates}
    for ref_sha in advisory.fixed_commits | advisory.reference_commits:
        ref_sha_clean = ref_sha.lower().replace("commit::", "")
        if ref_sha_clean not in existing_ids:
            explicit_commit = repo.get_commit_by_id(ref_sha_clean)
            if explicit_commit:
                candidates.append(explicit_commit)
                existing_ids.add(explicit_commit.commit_id.lower())

    if show_progress:
        print(f"→ [1/3] Git log scanned: found {len(candidates)} candidate commits")

    # 5. Fast initial heuristic ranking
    ranked = rank_candidates(advisory, candidates)

    # 5b. Fetch full diffs for top candidates (top 50) and evaluate code diff rules
    top_candidates = ranked[:50]
    if fetch_diff and top_candidates:
        repo.populate_diffs_for_commits(top_candidates, show_progress=show_progress)
        from rules import ChangesRelevantCode
        code_rule = ChangesRelevantCode()
        for c in top_candidates:
            if c.diff:
                matched, reason = code_rule.apply(c, advisory)
                if matched and not any(r["rule"] == code_rule.id for r in c.matched_rules):
                    c.score += code_rule.weight
                    c.matched_rules.append({
                        "rule": code_rule.id,
                        "weight": code_rule.weight,
                        "reason": reason,
                    })

    # 5c. Optional semantic embedding re-ranking on top candidates
    if use_embeddings and ranked:
        from embeddings import apply_semantic_embeddings
        apply_semantic_embeddings(
            advisory=advisory,
            candidates=ranked,
            model_name_or_path=embedding_model,
            top_n_to_rerank=50,
            show_progress=show_progress,
        )

    # Final sort
    pub_time = advisory.published_timestamp
    def sort_key(c):
        time_dist = abs(c.timestamp - pub_time) if (pub_time and c.timestamp) else 9999999999
        return (c.score, -time_dist)
    ranked.sort(key=sort_key, reverse=True)

    top_commits = ranked[:top_k] if top_k else ranked

    return {
        "vuln_id": advisory.id,
        "aliases": advisory.aliases,
        "package": advisory.package_name,
        "repo_path": repo_path,
        "tag_range": tag_range,
        "total_candidates": len(candidates),
        "top_commit": ranked[0].commit_id if ranked else None,
        "top_score": ranked[0].score if ranked else 0,
        "ranked_commits": [c.to_dict() for c in top_commits],
    }
