import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CandidateCommit:
    commit_id: str
    timestamp: int
    author: str
    message: str
    changed_files: List[str] = field(default_factory=list)
    diff: List[str] = field(default_factory=list)
    hunks: int = 0
    score: int = 0
    matched_rules: List[dict] = field(default_factory=list)

    @property
    def short_id(self) -> str:
        return self.commit_id[:8]

    def to_dict(self, include_diff: bool = False) -> dict:
        d = {
            "commit_id": self.commit_id,
            "short_id": self.short_id,
            "score": self.score,
            "timestamp": self.timestamp,
            "author": self.author,
            "message": self.message.split("\n")[0] if self.message else "",
            "changed_files": self.changed_files,
            "matched_rules": self.matched_rules,
        }
        if include_diff:
            d["diff"] = self.diff
        return d


class GitRepo:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        if not os.path.isdir(os.path.join(self.repo_path, ".git")) and not os.path.isfile(os.path.join(self.repo_path, "HEAD")):
            raise ValueError(f"Not a valid git repository: {self.repo_path}")

    def _run_git(self, args: List[str], timeout: int = 30) -> str:
        cmd = ["git", "-C", self.repo_path] + args
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if res.returncode != 0:
            raise RuntimeError(f"Git command failed: {' '.join(cmd)}\nStderr: {res.stderr.strip()}")
        return res.stdout

    def get_tags(self) -> List[str]:
        """Return all tags in the repository."""
        out = self._run_git(["tag", "-l"])
        return [t.strip() for t in out.splitlines() if t.strip()]

    def tag_exists(self, tag: str) -> bool:
        try:
            self._run_git(["rev-parse", "--verify", f"refs/tags/{tag}"])
            return True
        except RuntimeError:
            return False

    def find_matching_tag(self, version_str: str, package_name: Optional[str] = None) -> Optional[str]:
        """Match a version string (e.g. '9.0.0') to an actual Git tag in the repository."""
        if not version_str:
            return None
        version_str = version_str.strip().lstrip("v")
        tags = self.get_tags()
        if not tags:
            return None

        # 1. Exact match
        if version_str in tags:
            return version_str
        # 2. 'v' prefix
        if f"v{version_str}" in tags:
            return f"v{version_str}"
        # 3. Package-prefixed tags (e.g. 'zip-9.0.0', 'zip-v9.0.0', 'zip_9.0.0')
        if package_name:
            pkg = package_name.lower().replace("_", "-")
            for prefix in [f"{pkg}-{version_str}", f"{pkg}-v{version_str}", f"{pkg}_{version_str}", f"{pkg}_v{version_str}"]:
                if prefix in tags:
                    return prefix
        # 4. Release prefixes
        for prefix in [f"release-{version_str}", f"release-v{version_str}", f"release/{version_str}", f"rel-{version_str}"]:
            if prefix in tags:
                return prefix

        # 5. Regex boundary match (e.g. 'v9.0.0-rc1', 'archive-9.0.0')
        pattern = re.compile(rf"(?:^|[_\-/v]){re.escape(version_str)}(?:$|[_\-/\.])", re.IGNORECASE)
        for t in tags:
            if pattern.search(t):
                return t
        return None

    def resolve_range(self, tag_range: Optional[str] = None) -> Optional[str]:
        """
        Normalize range notation:
        'v1.0:v2.0' -> 'v1.0..v2.0'
        'v1.0..v2.0' -> 'v1.0..v2.0'
        'v2.0' -> 'v2.0'
        """
        if not tag_range:
            return None
        tag_range = tag_range.strip()
        if ":" in tag_range:
            parts = tag_range.split(":", 1)
            p1, p2 = parts[0].strip(), parts[1].strip()
            m1 = self.find_matching_tag(p1) or p1
            m2 = self.find_matching_tag(p2) or p2
            return f"{m1}..{m2}"
        if ".." in tag_range:
            return tag_range
        return self.find_matching_tag(tag_range) or tag_range

    def get_commit_by_id(self, commit_id: str) -> Optional[CandidateCommit]:
        """Fetch a single commit by hash."""
        args = [
            "log",
            "--name-only",
            "--format=COMMIT_START%n%H%n%at%n%an%n%B%nCOMMIT_MSG_END",
            "-n1",
            commit_id,
        ]
        try:
            out = self._run_git(args, timeout=10)
            parsed = self._parse_git_log(out)
            if parsed:
                self._populate_diffs(parsed)
                return parsed[0]
        except Exception:
            return None
        return None

    def get_commits(
        self,
        tag_range: Optional[str] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
        max_candidates: int = 2000,
        fetch_diff: bool = True,
    ) -> List[CandidateCommit]:
        """
        Extract candidate commits using `git log`.
        Supports tag_range ('tagA..tagB') or timestamps (since/until).
        """
        args = [
            "log",
            "--name-only",
            "--format=COMMIT_START%n%H%n%at%n%an%n%B%nCOMMIT_MSG_END",
            f"-n{max_candidates}",
        ]

        resolved_range = self.resolve_range(tag_range)
        if resolved_range:
            args.append(resolved_range)
        else:
            args.append("HEAD")

        if until:
            args.append(f"--until={until}")
        if since:
            args.append(f"--since={since}")

        try:
            raw_output = self._run_git(args, timeout=60)
        except RuntimeError as e:
            # Fallback if rev range failed (e.g. tag doesn't exist)
            if resolved_range and ".." in resolved_range:
                # Try just the second tag or HEAD
                end_tag = resolved_range.split("..")[-1]
                args_fallback = [
                    "log",
                    "--name-only",
                    "--format=COMMIT_START%n%H%n%at%n%an%n%B%nCOMMIT_MSG_END",
                    f"-n{max_candidates}",
                    end_tag,
                ]
                raw_output = self._run_git(args_fallback, timeout=60)
            else:
                raise e

        commits = self._parse_git_log(raw_output)
        return commits

    def _parse_git_log(self, text: str) -> List[CandidateCommit]:
        commits: List[CandidateCommit] = []
        blocks = text.split("COMMIT_START\n")

        for block in blocks:
            if not block.strip():
                continue

            parts = block.split("COMMIT_MSG_END\n", 1)
            header_and_msg = parts[0]
            files_part = parts[1] if len(parts) > 1 else ""

            lines = header_and_msg.split("\n")
            if len(lines) < 4:
                continue

            commit_id = lines[0].strip()
            try:
                timestamp = int(lines[1].strip())
            except ValueError:
                timestamp = 0
            author = lines[2].strip()
            message = "\n".join(lines[3:]).strip()

            changed_files = [f.strip() for f in files_part.splitlines() if f.strip()]

            commits.append(
                CandidateCommit(
                    commit_id=commit_id,
                    timestamp=timestamp,
                    author=author,
                    message=message,
                    changed_files=changed_files,
                )
            )

        return commits

    def populate_diffs_for_commits(self, commits: List[CandidateCommit], show_progress: bool = False):
        """Populate full diffs for a subset of candidate commits."""
        import sys
        total = len(commits)
        for i, c in enumerate(commits):
            if show_progress:
                pct = int(((i + 1) / total) * 100)
                sys.stderr.write(f"\r→ [2/3] Reading full diffs: [ {i + 1} / {total} ] ({pct}%)")
                sys.stderr.flush()
            if c.diff:
                continue
            try:
                # Full diff with no line cap
                diff_out = self._run_git(["show", "--format=", "--unified=1", c.commit_id], timeout=30)
                diff_lines = diff_out.splitlines()
                c.diff = diff_lines
                c.hunks = sum(1 for line in diff_lines if line.startswith("@@"))
            except Exception:
                pass
        if show_progress and total > 0:
            sys.stderr.write(" [Done]\n")

    def _populate_diffs(self, commits: List[CandidateCommit], show_progress: bool = False):
        self.populate_diffs_for_commits(commits, show_progress=show_progress)
