import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Set
from dateutil.parser import isoparse

RELEVANT_EXTENSIONS = {
    "rs", "toml", "c", "cpp", "h", "java", "py", "go", "js", "ts",
    "rb", "php", "sh", "lua", "swift", "sql", "yaml", "yml"
}

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an",
    "and", "any", "are", "aren't", "as", "at", "be", "because", "been",
    "before", "being", "below", "between", "both", "but", "by", "can",
    "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does",
    "doesn't", "doing", "don't", "down", "during", "each", "few", "for",
    "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't",
    "having", "he", "he'd", "he'll", "he's", "her", "here", "here's",
    "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd",
    "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my",
    "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or",
    "other", "ought", "our", "ours", "ourselves", "out", "over", "own",
    "same", "shan't", "she", "she'd", "she'll", "she's", "should",
    "shouldn't", "so", "some", "such", "than", "that", "that's", "the",
    "their", "theirs", "them", "themselves", "then", "there", "there's",
    "these", "they", "they'd", "they'll", "they're", "they've", "this",
    "those", "through", "to", "too", "under", "until", "up", "very", "was",
    "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't",
    "what", "what's", "when", "when's", "where", "where's", "which", "while",
    "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your",
    "yours", "yourself", "yourselves"
}


def extract_keywords(text: str) -> Set[str]:
    """Extract descriptive keywords from text (lowercase, length > 3, alphanumeric, non-stopword)."""
    words = re.findall(r"\b[a-zA-Z]{4,}\b", text.lower())
    return {w for w in words if w not in STOP_WORDS}


def extract_filenames(text: str) -> Set[str]:
    """Extract source code filenames mentioned in advisory description."""
    filenames = set()
    # Match patterns like parser.rs, foo_bar.c, Lib/utils.py
    for match in re.finditer(r"\b([a-zA-Z0-9_\-\./]+\.([a-zA-Z0-9]+))\b", text):
        full_match, ext = match.group(1), match.group(2).lower()
        if ext in RELEVANT_EXTENSIONS:
            # take basename
            basename = full_match.split("/")[-1].split("\\")[-1]
            filenames.add(basename)
            filenames.add(basename.rsplit(".", 1)[0])
    return filenames


class Advisory:
    def __init__(self, data: dict):
        self.raw = data
        self.id: str = data.get("id", "")
        self.aliases: List[str] = data.get("aliases", [])
        self.description: str = data.get("details") or data.get("summary") or ""
        self.summary: str = data.get("summary", "")

        # Timestamps
        self.published_timestamp: Optional[int] = None
        if data.get("published"):
            try:
                self.published_timestamp = int(isoparse(data["published"]).timestamp())
            except Exception:
                pass

        self.modified_timestamp: Optional[int] = None
        if data.get("modified"):
            try:
                self.modified_timestamp = int(isoparse(data["modified"]).timestamp())
            except Exception:
                pass

        # Package & Repo
        self.package_name: str = ""
        self.repo_url: str = ""
        self.affected_versions: List[str] = []
        self.fixed_versions: List[str] = []
        self.fixed_commits: Set[str] = set()

        # Parse affected section
        for affected in data.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name") and not self.package_name:
                self.package_name = pkg.get("name")

            if "versions" in affected:
                self.affected_versions.extend(affected["versions"])

            for r in affected.get("ranges", []):
                if r.get("type") == "GIT":
                    if r.get("repo") and not self.repo_url:
                        self.repo_url = r.get("repo")
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            self.fixed_commits.add(ev["fixed"])
                elif r.get("type") in ("SEMVER", "ECOSYSTEM"):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            self.fixed_versions.append(ev["fixed"])

        # References
        self.references: List[str] = []
        self.reference_commits: Set[str] = set()
        self.issue_refs: Set[str] = set()

        for ref in data.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
            self.references.append(url)

            # Check if reference contains a commit hash
            commit_match = re.search(r"/(?:commit|commits)/([0-9a-f]{7,40})", url, re.IGNORECASE)
            if commit_match:
                sha = commit_match.group(1).lower()
                self.reference_commits.add(sha)
                if ref.get("type") == "FIX":
                    self.fixed_commits.add(sha)

            # Check if reference contains an issue/PR number
            issue_match = re.search(r"/(?:issues|pull)/(\d+)", url)
            if issue_match:
                self.issue_refs.add(issue_match.group(1))

        # Extracted NLP metadata
        self.keywords: Set[str] = extract_keywords(self.description)
        self.files: Set[str] = extract_filenames(self.description)

        # All target identifiers for matching
        self.all_ids: Set[str] = {self.id.upper()}
        for a in self.aliases:
            self.all_ids.add(a.upper())

    @classmethod
    def from_file(cls, filepath: str) -> "Advisory":
        """Load an advisory from a local JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def __repr__(self):
        return f"<Advisory id={self.id} aliases={self.aliases} fixed_commits={len(self.fixed_commits)}>"
