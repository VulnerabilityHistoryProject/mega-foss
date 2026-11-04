import re
from typing import Dict, List, Optional, Set, Tuple
from advisory import Advisory
from git_ops import CandidateCommit

SEC_KEYWORDS = {
    "vuln", "vulnerable", "vulnerability", "exploit", "attack", "security",
    "secure", "xxe", "xss", "cross-site", "dos", "denial of service",
    "command injection", "insecure", "inject", "injection", "unsafe",
    "remote execution", "malicious", "sanitize", "sanitization",
    "man-in-the-middle", "mitm", "cwe", "rce", "sqli", "sql injection",
    "buffer overflow", "hijack", "hardening", "hardened", "patch", "fix",
    "overflow", "bypass", "unauthorized", "privilege escalation"
}


class Rule:
    def __init__(self, id: str, weight: int, description: str):
        self.id = id
        self.weight = weight
        self.description = description

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        raise NotImplementedError


class VulnIdInMessage(Rule):
    def __init__(self):
        super().__init__("VULN_ID_IN_MESSAGE", 64, "Commit message mentions the vulnerability ID or alias")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        for vid in advisory.all_ids:
            if not vid:
                continue
            if re.search(rf"\b{re.escape(vid)}\b", commit.message, re.IGNORECASE):
                return True, f"Found vulnerability ID '{vid}' in commit message"
        return False, ""


class CommitInReference(Rule):
    def __init__(self):
        super().__init__("COMMIT_IN_REFERENCE", 64, "Commit SHA is explicitly listed in advisory fix events or references")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        cid = commit.commit_id.lower()
        short = commit.short_id.lower()

        for ref_sha in advisory.fixed_commits | advisory.reference_commits:
            ref_sha_clean = ref_sha.lower().replace("commit::", "")
            if cid.startswith(ref_sha_clean) or ref_sha_clean.startswith(short):
                return True, f"Commit matches advisory referenced commit SHA: {ref_sha}"
        return False, ""


class CrossReferencedIssue(Rule):
    def __init__(self):
        super().__init__("XREF_ISSUE", 32, "Commit references an issue/PR that is also in the advisory references")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        # Extract #123, gh-123, or pull/123 from commit message
        commit_issues = set(re.findall(r"(?:#|gh-|pull/)(\d{1,6})", commit.message, re.IGNORECASE))
        matched = commit_issues.intersection(advisory.issue_refs)

        # Also check against raw reference URLs in advisory
        if not matched and commit_issues:
            for ref_url in advisory.references:
                for issue_num in commit_issues:
                    if f"/{issue_num}" in ref_url or f"#{issue_num}" in ref_url:
                        matched.add(issue_num)

        if matched:
            return True, f"Issue/PR numbers referenced in both commit and advisory: {', '.join(matched)}"
        return False, ""


class ChangesRelevantFiles(Rule):
    def __init__(self):
        super().__init__("CHANGES_RELEVANT_FILES", 8, "Commit modifies files explicitly named in the advisory description")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if not advisory.files:
            return False, ""

        matched_files = set()
        for f in commit.changed_files:
            f_base = f.split("/")[-1]
            for adv_file in advisory.files:
                if len(adv_file) > 2 and (adv_file.lower() == f_base.lower() or adv_file.lower() in f.lower()):
                    matched_files.add(f_base)

        if matched_files:
            return True, f"Changed files match advisory filenames: {', '.join(matched_files)}"
        return False, ""


class ChangesRelevantCode(Rule):
    def __init__(self):
        super().__init__("CHANGES_RELEVANT_CODE", 8, "Commit diff touches methods or filenames mentioned in advisory")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if not advisory.files or not commit.diff:
            return False, ""

        matched = set()
        for adv_file in advisory.files:
            if len(adv_file) <= 2:
                continue
            adv_lower = adv_file.lower()
            for line in commit.diff:
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                    if adv_lower in line.lower():
                        matched.add(adv_file)
                        break

        if matched:
            return True, f"Diff touches terms from advisory: {', '.join(matched)}"
        return False, ""


class RelevantWordsInMessage(Rule):
    def __init__(self):
        super().__init__("RELEVANT_WORDS_IN_MESSAGE", 8, "Commit message contains relevant filenames/components from advisory")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if not advisory.files:
            return False, ""

        matched = set()
        msg_lower = commit.message.lower()
        for term in advisory.files:
            if len(term) > 3 and term.lower() in msg_lower:
                matched.add(term)

        if matched:
            return True, f"Message mentions relevant component: {', '.join(matched)}"
        return False, ""


class AdvKeywordsInFiles(Rule):
    def __init__(self):
        super().__init__("ADV_KEYWORDS_IN_FILES", 4, "Changed file paths contain keywords extracted from advisory")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if not advisory.keywords or not commit.changed_files:
            return False, ""

        matched = set()
        for f in commit.changed_files:
            f_lower = f.lower()
            for kw in advisory.keywords:
                if kw in f_lower:
                    matched.add(kw)

        if matched:
            return True, f"Changed paths contain advisory keywords: {', '.join(list(matched)[:5])}"
        return False, ""


class AdvKeywordsInMsg(Rule):
    def __init__(self):
        super().__init__("ADV_KEYWORDS_IN_MSG", 4, "Commit message contains keywords extracted from advisory")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if not advisory.keywords:
            return False, ""

        msg_words = set(re.findall(r"\b[a-zA-Z]{4,}\b", commit.message.lower()))
        matched = msg_words.intersection(advisory.keywords)

        if len(matched) >= 2:  # require at least 2 keywords to avoid random noise
            return True, f"Message shares keywords with advisory: {', '.join(list(matched)[:5])}"
        return False, ""


class SecurityKeywordsInMsg(Rule):
    def __init__(self):
        super().__init__("SEC_KEYWORDS_IN_MESSAGE", 4, "Commit message contains security-related keywords")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        msg_words = set(re.findall(r"\b[a-zA-Z\-]{3,}\b", commit.message.lower()))
        matched = msg_words.intersection(SEC_KEYWORDS)

        if matched:
            return True, f"Message contains security terms: {', '.join(matched)}"
        return False, ""


class ReferencesIssue(Rule):
    def __init__(self):
        super().__init__("GITHUB_ISSUE_IN_MESSAGE", 2, "Commit message references an issue or PR number")

    def apply(self, commit: CandidateCommit, advisory: Advisory) -> Tuple[bool, str]:
        if re.search(r"(?:#|gh-|pull/)\d{1,6}\b", commit.message):
            return True, "Commit message contains issue reference"
        return False, ""


DEFAULT_RULES: List[Rule] = [
    VulnIdInMessage(),
    CommitInReference(),
    CrossReferencedIssue(),
    ChangesRelevantFiles(),
    ChangesRelevantCode(),
    RelevantWordsInMessage(),
    AdvKeywordsInFiles(),
    AdvKeywordsInMsg(),
    SecurityKeywordsInMsg(),
    ReferencesIssue(),
]
