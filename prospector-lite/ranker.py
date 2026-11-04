from typing import List, Optional
from advisory import Advisory
from git_ops import CandidateCommit
from rules import DEFAULT_RULES, Rule


def rank_candidates(
    advisory: Advisory,
    candidates: List[CandidateCommit],
    rules: Optional[List[Rule]] = None,
) -> List[CandidateCommit]:
    """
    Apply heuristic rules to all candidate commits and sort them by relevance score.
    """
    if rules is None:
        rules = DEFAULT_RULES

    for commit in candidates:
        commit.score = 0
        commit.matched_rules = []

        for rule in rules:
            matched, reason = rule.apply(commit, advisory)
            if matched:
                commit.score += rule.weight
                commit.matched_rules.append({
                    "rule": rule.id,
                    "weight": rule.weight,
                    "reason": reason,
                })

    # Sort primarily by score descending.
    # Tie-break by proximity to the advisory's publication timestamp if available.
    pub_time = advisory.published_timestamp

    def sort_key(c: CandidateCommit):
        time_dist = abs(c.timestamp - pub_time) if (pub_time and c.timestamp) else 9999999999
        return (c.score, -time_dist)

    candidates.sort(key=sort_key, reverse=True)
    return candidates
