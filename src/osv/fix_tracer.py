"""Find the commit in a source repository that fixed a single OSV vulnerability.

Usage:
    python3 src/osv/fix_tracer.py GHSA-xxxx-xxxx-xxxx [--ecosystem npm] [--repo-path DIR]

Steps:
  1. Load <ID>.json from <OSV_JSON_PATH>/<ecosystem>/all.zip.
  2. Collect candidate fix commits: OSV GIT ranges and commit references, plus the
     commits in a date window. The window starts at the newest git tag matching an
     affected version (tag dates are cached per repo) and ends at a later fixed
     tag, else shortly after the publication date.
  3. Embed each candidate (message + files + diff, optionally an LLM summary),
     cached per commit SHA so repeated runs and sibling jobs reuse the work.
  4. Rank by cosine similarity combined with temporal, path, keyword and
     reference signals, then ask the LLM to explain the top matches.
  5. Write <OSV_OUTPUT_PATH>/tracer/<ID>.json and <ID>.md.

Defaults come from settings.ini (REPOSITORIES_PATH, OSV_*); relative paths
resolve from the repository root. Repositories are looked up in the
REPOSITORY_LIST csv (repo,url) and expected at <REPOSITORIES_PATH>/<repo>,
where bulk_clone_repositories.sh puts them.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import orjson

sys.path.insert(0, str(Path(__file__).resolve().parent))
from download_ecosystem import load_settings, resolve  # noqa: E402

PROMPT_VERSION = "v1"
T0 = time.monotonic()


def log(msg: str) -> None:
    print(f"[{time.monotonic() - T0:7.1f}s] {msg}", file=sys.stderr, flush=True)


WEIGHTS = {"semantic": 0.63, "reference": 0.15, "path": 0.10, "temporal": 0.02, "keyword": 0.10}
KEYWORDS = re.compile(
    r"\b(cve-\d{4}-\d+|ghsa-[\w-]+|security|vulnerab\w*|exploit\w*|sanitiz\w*|escap\w*|"
    r"overflow|injection|xss|traversal|bypass|denial|dos|fix\w*)\b", re.I)
COMMIT_URL = re.compile(r"/commits?/([0-9a-f]{7,40})\b")
MAX_DIFF_CHARS = 6000


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                         text=True, errors="replace")
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def require_zip(zip_path: Path, ecosystem: str) -> None:
    if not zip_path.exists():
        raise SystemExit(
            f"OSV data not found: {zip_path}\n"
            f"Download it first with: python src/osv/download_ecosystem.py --ecosystem {ecosystem}")


def load_vuln(zip_path: Path, vuln_id: str) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        try:
            return orjson.loads(zf.read(f"{vuln_id}.json"))
        except KeyError:
            raise SystemExit(f"{vuln_id}.json not found in {zip_path}")


def blind(vuln: dict) -> dict:
    """Remove the answer (GIT fixed events, commit-URL references) for evaluation."""
    vuln = json.loads(json.dumps(vuln))
    for a in vuln.get("affected", []):
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                r["events"] = [e for e in r.get("events", []) if "fixed" not in e]
    vuln["references"] = [r for r in vuln.get("references", [])
                          if not COMMIT_URL.search(r.get("url", ""))]
    return vuln


def vuln_text(vuln: dict) -> str:
    return "\n".join(filter(None, [vuln.get("summary"), vuln.get("details")])).strip()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_package_map(path: str | None) -> dict[tuple[str, str], str]:
    """Map (ecosystem, package) -> repo ('owner/name' clone folder) from the package CSV."""
    if not path or not resolve(path).exists():
        return {}
    with open(resolve(path), newline="") as f:
        return {(r["ecosystem"].strip().lower(), r["package"].strip().lower()): r["repo"].strip()
                for r in csv.DictReader(f) if r.get("ecosystem") and r.get("package") and r.get("repo")}


def vuln_packages(vuln: dict) -> list[tuple[str, str]]:
    """(ecosystem, package) pairs of the record; 'Ubuntu:Pro:14.04:LTS' reduces to 'ubuntu'."""
    pairs = []
    for a in vuln.get("affected", []):
        pkg = a.get("package") or {}
        if pkg.get("name"):
            pair = (pkg.get("ecosystem", "").split(":")[0].lower(), pkg["name"].lower())
            if pair not in pairs:
                pairs.append(pair)
    return pairs


def find_package_repo(vuln: dict, package_map: dict[tuple[str, str], str]) -> str | None:
    return next((package_map[p] for p in vuln_packages(vuln) if p in package_map), None)


def direct_fixes(vuln: dict) -> list[str]:
    return [e["fixed"] for a in vuln.get("affected", []) for r in a.get("ranges", [])
            if r.get("type") == "GIT" for e in r.get("events", []) if "fixed" in e]


def referenced_commits(vuln: dict) -> list[str]:
    return [m.group(1) for r in vuln.get("references", [])
            if (m := COMMIT_URL.search(r.get("url", "")))]


def affected_versions(vuln: dict) -> list[tuple[str, str]]:
    """(version, ecosystem) for every affected package version the record names."""
    out = []
    for a in vuln.get("affected", []):
        eco = a.get("package", {}).get("ecosystem", "")
        out += [(v, eco) for v in a.get("versions", [])]
        for r in a.get("ranges", []):
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                out += [(e[k], eco) for e in r.get("events", [])
                        for k in ("introduced", "last_affected") if e.get(k) and e[k] != "0"]
    return out


def fixed_versions(vuln: dict) -> list[tuple[str, str]]:
    return [(e["fixed"], a.get("package", {}).get("ecosystem", ""))
            for a in vuln.get("affected", []) for r in a.get("ranges", [])
            if r.get("type") in ("SEMVER", "ECOSYSTEM") for e in r.get("events", []) if "fixed" in e]


def upstream_versions(version: str, ecosystem: str) -> list[str]:
    """Upstream version candidates for a package version, most specific first.

    Distro versions carry an epoch and packaging revision ("6:9.20-0ubuntu0.14.04.1+esm1"
    -> "9.20"), which never appear in upstream git tags.
    """
    v = re.sub(r"^\d+:", "", version.strip())
    eco = ecosystem.lower()
    if eco.startswith(("ubuntu", "debian")) and "-" in v:
        v = v.rsplit("-", 1)[0]
    elif eco.startswith("alpine"):
        v = re.sub(r"-r\d+$", "", v)
    v = re.sub(r"\+(dfsg|ds|repack|really|git|svn|hg|bzr|esm|deb|ubuntu|build|nmu)[\w.+~-]*$", "", v)
    cands = [v.replace("~", "-").lower()]
    base = re.split(r"[~+]", v)[0].lower()  # drop pre-release/local suffix as a fallback
    if base and base not in cands:
        cands.append(base)
    return [c for c in cands if c]


def tag_version(tag: str) -> str:
    """Strip name/prefix from a tag: n9.0.2, v1.2, release/4.4, OpenSSL_1_1_1k -> version."""
    v = re.sub(r"^[^\d]*", "", tag)
    if "." not in v and "_" in v:
        v = v.replace("_", ".")
    return v.lower()


def numeric_parts(version: str) -> tuple[int, ...]:
    m = re.match(r"\d+(?:\.\d+)*", version)
    return tuple(int(x) for x in m.group(0).split(".")) if m else ()


def common_prefix(a: tuple, b: tuple) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def git_common_dir(repo: Path) -> Path:
    out = Path(git(repo, "rev-parse", "--git-common-dir").strip())
    return out if out.is_absolute() else repo / out


def tag_dates(repo: Path, cache_dir: Path, refresh: bool = False) -> dict[str, str]:
    """{tag: commit date (ISO)} for every tag, read once per repo and cached.

    The cache is rebuilt when the repo's tag refs change (or with --refresh-tags).
    """
    gd = git_common_dir(repo)
    stamp = [(gd / n).stat().st_mtime if (gd / n).exists() else 0 for n in ("packed-refs", "refs/tags")]
    path = cache_dir / "tags" / f"{hashlib.sha1(str(repo.resolve()).encode()).hexdigest()[:12]}.json"
    if path.exists() and not refresh:
        cached = json.loads(path.read_text())
        if cached.get("stamp") == stamp:
            return cached["tags"]
    # *committerdate is the target commit of an annotated tag; committerdate covers lightweight tags
    fmt = "%(refname)%09%(*committerdate:iso-strict)%09%(committerdate:iso-strict)"
    tags = {}
    for line in git(repo, "for-each-ref", f"--format={fmt}", "refs/tags").splitlines():
        name, deref, direct = (line.split("\t") + ["", ""])[:3]
        if name and (deref or direct):
            tags[name.removeprefix("refs/tags/")] = deref or direct
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"repo": str(repo), "stamp": stamp, "tags": tags}))
    os.replace(tmp, path)
    return tags


def match_version_tags(versions: list[tuple[str, str]], tags: dict[str, str],
                       exact_only: bool = False) -> list[dict]:
    """Map package versions to git tags: an exact tag, else the closest tags sharing a version prefix."""
    index: dict[str, tuple[str, str]] = {}
    for tag, date in tags.items():
        key = tag_version(tag)
        if key and (key not in index or parse_time(date) < parse_time(index[key][1])):
            index[key] = (tag, date)
    parsed = {key: numeric_parts(key) for key in index}

    matches, seen = [], set()
    for version, eco in versions:
        cands = upstream_versions(version, eco)
        if not cands or cands[0] in seen:
            continue
        seen.add(cands[0])
        exact = next((c for c in cands if c in index), None)
        if exact:
            tag, date = index[exact]
            matches.append({"version": version, "upstream": exact, "tag": tag, "date": date, "match": "exact"})
            continue
        parts = numeric_parts(cands[0])
        if exact_only or not parts:
            continue
        need = min(2, len(parts))  # at least major.minor must agree
        best, group = 0, []
        for key, kparts in parsed.items():
            n = common_prefix(parts, kparts)
            if n < need:
                continue
            if n > best:
                best, group = n, []
            if n == best:
                group.append(index[key])
        if group:
            tag, date = min(group, key=lambda t: parse_time(t[1]))  # earliest of the closest tags
            matches.append({"version": version, "upstream": cands[0], "tag": tag, "date": date,
                            "match": f"similar ({best} version parts)"})
    return matches


def candidate_window(matches, fixed_matches, published, days_before, days_after, tag_buffer=30):
    """(start, end, source). The bug exists in every affected release, so the fix
    landed around the newest affected tag (minus a buffer for release delays); it ends at a later fixed tag, else shortly
    after the OSV publication date. Falls back to a window around publication."""
    if matches:
        tag_date = max(parse_time(m["date"]) for m in matches)
        start = tag_date - timedelta(days=tag_buffer)  # fixes land before the release is tagged
        later = [d for m in fixed_matches if (d := parse_time(m["date"])) > tag_date]
        if later:
            return start, min(later), "newest affected tag -> fixed tag"
        if published and published + timedelta(days=days_after) > tag_date:
            return start, published + timedelta(days=days_after), "newest affected tag -> published"
    if published:
        return (published - timedelta(days=days_before), published + timedelta(days=days_after),
                "published date window")
    return None


def resolve_sha(repo: Path, ref: str) -> str | None:
    try:
        return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    except RuntimeError:
        return None


def mentioned_terms(text: str) -> set[str]:
    """File names, paths and code-like identifiers the description points at."""
    terms = set(re.findall(r"[\w./-]+\.\w{1,5}\b", text))
    terms |= set(re.findall(r"`([^`]{3,60})`", text))
    terms |= {t for t in re.findall(r"\b[a-z]+(?:_[a-z0-9]+)+\b|\b[a-z]+[A-Z]\w+\b", text)}
    return {t.lower() for t in terms if len(t) >= 4}


def list_window_commits(repo: Path, start: datetime, end: datetime) -> list[dict]:
    fmt = "%x1e%H%x1f%cI%x1f%s"
    out = git(repo, "log", "--no-merges", "--name-only", f"--since={start.isoformat()}",
              f"--until={end.isoformat()}", f"--format={fmt}")
    commits = []
    for record in out.split("\x1e")[1:]:
        header, _, names = record.partition("\n")
        sha, date, subject = header.split("\x1f", 2)
        commits.append({"sha": sha, "date": date, "subject": subject,
                        "files": [n for n in names.splitlines() if n]})
    return commits


def commit_details(repo: Path, sha: str) -> dict:
    meta = git(repo, "show", "-s", "--format=%cI%x1f%B", sha)
    date, _, message = meta.partition("\x1f")
    files = git(repo, "show", "--format=", "--name-only", sha).split()
    diff = git(repo, "show", "--format=", "--unified=2", sha)[:MAX_DIFF_CHARS]
    return {"sha": sha, "date": date.strip(), "message": message.strip(),
            "files": files, "diff": diff}


class Llm:
    """Client for an OpenAI-compatible API (/embeddings and /chat/completions)."""

    def __init__(self, base_url: str, api_key: str, embed_model: str, chat_model: str,
                 summarize: bool, tokens_per_minute: int = 0):
        local = re.match(r"https?://(localhost|127\.0\.0\.1)(:|/|$)", base_url)
        if not api_key and not local:
            raise SystemExit("No API key: set FIX_TRACER_API_KEY in settings.ini (or pass --api-key)")
        import requests
        self.http = requests.Session()
        if api_key:  # a local Ollama server needs no key
            self.http.headers["Authorization"] = f"Bearer {api_key}"
        self.base_url = base_url.rstrip("/")
        self.embed_model = embed_model
        self.chat_model = chat_model
        self.summarize = summarize
        self.tokens_per_minute = tokens_per_minute
        self.window: list[list] = []  # [monotonic time, tokens] per request

    def estimate_tokens(self, payload: dict) -> int:
        """Rough count (~4 characters per token); the API's own count is logged afterwards."""
        text = payload.get("input") or "".join(m["content"] for m in payload.get("messages", []))
        return max(1, len(text) // 4)

    def recent(self) -> tuple[int, int]:
        """(requests, tokens) sent by this process in the last 60 seconds."""
        cutoff = time.monotonic() - 60
        self.window = [w for w in self.window if w[0] >= cutoff]
        return len(self.window), sum(w[1] for w in self.window)

    def throttle(self, est: int) -> None:
        """Sleep until sending `est` more tokens stays under the per-minute budget."""
        while self.tokens_per_minute:
            reqs, toks = self.recent()
            if toks + est <= self.tokens_per_minute or not self.window:
                return
            wait = max(self.window[0][0] + 60 - time.monotonic(), 0.5)
            log(f"  throttling {wait:.0f}s: {toks} tokens used in last 60s "
                f"+ ~{est} would exceed {self.tokens_per_minute}/min")
            time.sleep(wait)

    def post(self, path: str, payload: dict) -> dict:
        est = self.estimate_tokens(payload)
        for attempt in range(5):
            self.throttle(est)
            entry = [time.monotonic(), est]
            self.window.append(entry)
            reqs, toks = self.recent()
            log(f"  -> {path} ~{est} tokens | last 60s (this process): {reqs} requests, ~{toks} tokens"
                + (f" of {self.tokens_per_minute}" if self.tokens_per_minute else ""))
            resp = self.http.post(f"{self.base_url}{path}", json=payload, timeout=120)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < 4:
                log(f"  API {path} returned HTTP {resp.status_code}; retry {attempt + 1}/4 in {2 ** attempt}s")
                time.sleep(2 ** attempt)  # many array tasks share the API; back off
                continue
            if not resp.ok:
                raise RuntimeError(f"{path} returned HTTP {resp.status_code}: {resp.text[:300]}")
            data = resp.json()
            usage = data.get("usage")
            if usage:
                entry[1] = usage.get("total_tokens", entry[1])  # replace the estimate
                log(f"  <- {path} actual usage: {usage}")
            return data

    def embed(self, text: str, kind: str = "document") -> np.ndarray:
        data = self.post("/embeddings", {"model": self.embed_model, "input": text[:8000]})
        return np.array(data["data"][0]["embedding"], dtype=np.float32)

    def chat(self, prompt: str) -> str:
        data = self.post("/chat/completions", {"model": self.chat_model,
                                               "messages": [{"role": "user", "content": prompt}]})
        return data["choices"][0]["message"]["content"].strip()

    def summarize_commit(self, c: dict) -> str:
        return self.chat(
            "Describe in 2-3 sentences what this commit changes and, if it is a security "
            "fix, what weakness it addresses. Use only the text below.\n\n"
            f"Message:\n{c['message']}\n\nFiles: {', '.join(c['files'][:20])}\n\nDiff:\n{c['diff']}")


def commit_embedding(llm: Llm, repo: Path, sha: str, cache_dir: Path) -> dict:
    key = hashlib.sha1(f"{llm.base_url}|{llm.embed_model}|{llm.chat_model}|{llm.summarize}|{PROMPT_VERSION}".encode()).hexdigest()[:10]
    path = cache_dir / key / f"{sha}.json"
    if path.exists():
        return json.loads(path.read_text())
    c = commit_details(repo, sha)
    if llm.summarize:
        log(f"  {sha[:10]}: summarizing ({llm.chat_model})")
    c["summary"] = llm.summarize_commit(c) if llm.summarize else ""
    log(f"  {sha[:10]}: embedding ({llm.embed_model})")
    text = (f"{c['message']}\n\nFiles: {', '.join(c['files'][:30])}\n\n"
            f"{c['summary']}\n\n{c['diff']}")
    c["embedding"] = llm.embed(text, "document").tolist()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(c))
    os.replace(tmp, path)  # atomic: parallel SLURM tasks may share the cache
    return c


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float(a @ b) / denom if denom else 0.0


def prefilter_score(c: dict, terms: set[str], referenced: set[str]) -> float:
    subject = c["subject"].lower()
    s = 2.0 if any(c["sha"].startswith(r) for r in referenced) else 0.0
    s += 1.0 if KEYWORDS.search(c["subject"]) else 0.0
    s += 0.5 if any(t in subject for t in terms) else 0.0
    files = [f.lower() for f in c.get("files", [])]
    s += 1.5 if any(t in f for t in terms for f in files) else 0.0
    return s


def explain_signals(c: dict, s: dict, anchor: datetime | None) -> list[str]:
    bullets = [f"Semantic similarity between the OSV description and this commit: {s['semantic']:.2f}"]
    if s["reference"]:
        bullets.append("The OSV record's references link directly to this commit.")
    if s["path"]:
        bullets.append(f"{s['path']:.0%} of file/identifier names in the description appear in the changed files or diff.")
    if s["keyword"]:
        bullets.append("The commit message uses security/fix language (e.g. CVE ID, 'security', 'fix').")
    if anchor:
        days = abs((parse_time(c["date"]) - anchor).days)
        bullets.append(f"Committed {days} day(s) from the end of the candidate window ({anchor.date()}).")
    return bullets


def llm_rationale(llm: Llm, desc: str, c: dict, signals: list[str]) -> list[str]:
    reply = llm.chat(
        "You are explaining why a git commit does or does not fix a reported vulnerability. "
        "Write 3-6 markdown bullets ('- ...'). Each bullet must cite something concrete from "
        "the vulnerability description, commit message, or diff. If the evidence is weak or "
        "ambiguous, say so. Do not invent details.\n\n"
        f"Vulnerability:\n{desc}\n\nCommit message:\n{c['message']}\n\n"
        f"Files: {', '.join(c['files'][:20])}\n\nDiff:\n{c['diff']}\n\n"
        "Computed signals:\n" + "\n".join(f"- {b}" for b in signals))
    return [ln.lstrip("-* ").strip() for ln in reply.splitlines() if ln.strip().startswith(("-", "*"))]


def confidence(ranked: list[dict]) -> str:
    if not ranked:
        return "none"
    if ranked[0]["evidence"] == "osv_git_range":
        return "high"
    margin = ranked[0]["score"] - (ranked[1]["score"] if len(ranked) > 1 else 0)
    if ranked[0]["score"] >= 0.7 and margin >= 0.1:
        return "high"
    return "medium" if ranked[0]["score"] >= 0.5 else "low"  # uncalibrated heuristic


def trace(args, vuln: dict) -> dict:
    vuln_id = vuln["id"]
    desc = vuln_text(vuln)
    result = {"id": vuln_id, "description": desc, "status": "ok", "candidates": []}
    log(f"{vuln_id}: starting")

    repo = args.repo_path
    if not repo:
        slug = find_package_repo(vuln, load_package_map(args.package_map))
        if not slug:
            pairs = ", ".join(f"{e}/{n}" for e, n in vuln_packages(vuln)) or "no packages"
            log(f"{vuln_id}: no repo mapped for {pairs}; add a row to {args.package_map}")
            return {**result, "status": f"no_repo_found: {pairs}"}
        repo = resolve(args.repos_dir) / slug
    repo = Path(repo)
    if not (repo / ".git").exists() and not (repo / "HEAD").exists():
        return {**result, "status": f"repo_not_found: {repo}"}
    result["repo"] = str(repo)
    log(f"{vuln_id}: using repo {repo}")

    cache_dir = resolve(args.cache_dir)
    log(f"{vuln_id}: reading tag dates (cached per repo)")
    tags = tag_dates(repo, cache_dir, args.refresh_tags)
    published = parse_time(vuln.get("published"))
    matches = match_version_tags(affected_versions(vuln), tags)
    fixed_matches = match_version_tags(fixed_versions(vuln), tags, exact_only=True)
    window = candidate_window(matches, fixed_matches, published, args.days_before, args.days_after,
                              args.tag_buffer_days)
    anchor = window[1] if window else None
    result["version_matches"] = matches
    result["window"] = ({"start": window[0].isoformat(), "end": window[1].isoformat(), "source": window[2]}
                        if window else None)
    result["anchor"] = {"date": anchor.isoformat() if anchor else None,
                        "source": window[2] if window else "none"}
    log(f"{vuln_id}: {len(tags)} tags; {len(matches)} affected versions matched to tags; "
        + (f"window {window[0].date()} .. {window[1].date()} ({window[2]})" if window else "no date window"))

    direct = [s for ref in direct_fixes(vuln) if (s := resolve_sha(repo, ref))]
    referenced = [s for ref in referenced_commits(vuln) if (s := resolve_sha(repo, ref))]
    evidence = {s: "osv_git_range" for s in direct}
    evidence.update({s: "osv_reference" for s in referenced if s not in evidence})

    candidates = {}
    if window:
        in_window = list_window_commits(repo, window[0], window[1])
        terms = mentioned_terms(desc)
        center = max((parse_time(m["date"]) for m in matches), default=window[1])
        # Best score first; ties go to the commits closest to the affected release tag.
        in_window.sort(key=lambda c: (-prefilter_score(c, terms, set(evidence)),
                                      abs((parse_time(c["date"]) - center).total_seconds())))
        log(f"{vuln_id}: {len(in_window)} commits in window; keeping the top {args.max_candidates} by prefilter")
        candidates = {c["sha"]: "date_window" for c in in_window[:args.max_candidates]}
    candidates = {**candidates, **evidence}
    log(f"{vuln_id}: {len(candidates)} candidate commits ({len(evidence)} from OSV evidence)")
    result["num_candidates"] = len(candidates)
    if not candidates:
        return {**result, "status": "no_candidates"}

    llm = Llm(args.api_url, args.api_key, args.embed_model, args.chat_model, not args.no_summary,
              args.tokens_per_minute)
    log(f"{vuln_id}: embedding vulnerability description via {args.api_url}")
    query = llm.embed(f"{vuln.get('summary', '')}\n{desc}", "query")
    terms = mentioned_terms(desc)

    ranked = []
    for i, (sha, ev) in enumerate(candidates.items(), 1):
        if i == 1 or i % 10 == 0 or i == len(candidates):
            log(f"{vuln_id}: candidate {i}/{len(candidates)}")
        c = commit_embedding(llm, repo, sha, cache_dir)
        haystack = (" ".join(c["files"]) + "\n" + c["diff"]).lower()
        days = abs((parse_time(c["date"]) - anchor).days) if anchor else None
        signals = {
            "semantic": max(cosine(query, np.array(c["embedding"])), 0.0),
            "reference": 1.0 if sha in evidence else 0.0,
            "path": sum(t in haystack for t in terms) / len(terms) if terms else 0.0,
            "temporal": math.exp(-days / 180) if days is not None else 0.0,
            "keyword": 1.0 if KEYWORDS.search(c["message"]) else 0.0,
        }
        score = sum(WEIGHTS[k] * v for k, v in signals.items())
        ranked.append({"sha": sha, "date": c["date"], "subject": c["message"].splitlines()[0],
                       "evidence": ev, "score": round(score, 4),
                       "signals": {k: round(v, 4) for k, v in signals.items()}, "_c": c})
    ranked.sort(key=lambda r: r["score"], reverse=True)
    log(f"{vuln_id}: ranked; generating rationale for top {min(args.top_k, len(ranked))}")

    for r in ranked[:args.top_k]:
        c = r.pop("_c")
        log(f"  rationale for {r['sha'][:10]} (score {r['score']})")
        bullets = explain_signals(c, r["signals"], anchor)
        if r["evidence"] == "osv_git_range":
            bullets.insert(0, "The OSV record's GIT range lists this commit as the fix.")
        try:
            r["rationale"] = bullets + ["AI analysis: " + b for b in llm_rationale(llm, desc, c, bullets)]
        except Exception as e:  # keep deterministic evidence if the LLM call fails
            r["rationale"] = bullets + [f"AI analysis unavailable: {e}"]
    for r in ranked[args.top_k:]:
        r.pop("_c")
    result["candidates"] = ranked[:args.top_k]
    result["confidence"] = confidence(ranked)
    return result


def to_markdown(r: dict) -> str:
    lines = [f"# {r['id']}", "", f"Status: {r['status']}"]
    if r["status"] == "ok":
        w = r.get("window")
        lines += [f"Repo: {r['repo']}",
                  f"Candidate window: {w['start']} .. {w['end']} ({w['source']})" if w else "Candidate window: none",
                  f"Affected versions matched to tags: {len(r.get('version_matches', []))}",
                  f"Candidates considered: {r['num_candidates']}",
                  f"Confidence (heuristic): {r['confidence']}"]
        for i, c in enumerate(r["candidates"], 1):
            lines += ["", f"## {i}. {c['sha']} (score {c['score']})", "",
                      f"{c['subject']} — {c['date']}", ""]
            lines += [f"- {b}" for b in c["rationale"]]
    return "\n".join(lines) + "\n"


def build_parser(cfg: dict) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("vuln_id", help="OSV ID, e.g. GHSA-xxxx-xxxx-xxxx")
    p.add_argument("--ecosystem", default=cfg.get("OSV_ECOSYSTEM") or "npm")
    p.add_argument("--json-path", default=cfg.get("OSV_JSON_PATH") or "tmp/osv")
    p.add_argument("--output-path", default=cfg.get("OSV_OUTPUT_PATH") or "output/osv")
    p.add_argument("--package-map", default=cfg.get("FIX_TRACER_PACKAGE_MAP") or "lists/package_repos.csv",
                   help="CSV (ecosystem,package,repo) mapping packages to repo folders under --repos-dir")
    p.add_argument("--repos-dir", default=cfg.get("REPOSITORIES_PATH") or "")
    p.add_argument("--repo-path", help="Explicit repository path (overrides --repos-dir lookup)")
    p.add_argument("--cache-dir", default=cfg.get("FIX_TRACER_CACHE_PATH") or None, help="Embedding cache (default: <output-path>/tracer/cache, shared with test mode)")
    p.add_argument("--api-url", default=cfg.get("FIX_TRACER_API_URL") or "https://api.genai.gccis.rit.edu/v1",
                   help="OpenAI-compatible API base URL (default: FIX_TRACER_API_URL)")
    p.add_argument("--api-key", default=cfg.get("FIX_TRACER_API_KEY") or "",
                   help="API key (default: FIX_TRACER_API_KEY in settings.ini)")
    p.add_argument("--tokens-per-minute", type=int,
                   default=int(cfg.get("FIX_TRACER_TOKENS_PER_MINUTE") or 0),
                   help="Wait as needed to stay under this per-process budget; 0 = no limit")
    p.add_argument("--embed-model", default=cfg.get("FIX_TRACER_EMBED_MODEL") or "embeddinggemma:latest")
    p.add_argument("--chat-model", default=cfg.get("FIX_TRACER_CHAT_MODEL") or "qwen3:latest")
    p.add_argument("--no-summary", action="store_true", default=(cfg.get("FIX_TRACER_SUMMARIZE") or "true").lower() == "false", help="Skip per-commit LLM summaries")
    p.add_argument("--tag-buffer-days", type=int, default=int(cfg.get("FIX_TRACER_TAG_BUFFER_DAYS") or 30),
                   help="Days before the newest affected tag to start the candidate window")
    p.add_argument("--days-before", type=int, default=int(cfg.get("FIX_TRACER_DAYS_BEFORE") or 180))
    p.add_argument("--days-after", type=int, default=int(cfg.get("FIX_TRACER_DAYS_AFTER") or 14))
    p.add_argument("--max-candidates", type=int, default=int(cfg.get("FIX_TRACER_MAX_CANDIDATES") or 200))
    p.add_argument("--top-k", type=int, default=int(cfg.get("FIX_TRACER_TOP_K") or 3))
    p.add_argument("--refresh-tags", action="store_true",
                   help="Rebuild the cached tag dates for the repo (default: reuse until its tags change)")
    p.add_argument("--force", action="store_true", help="Re-run even if output exists")
    p.add_argument("--blind", action="store_true",
                   help="Test mode: hide the OSV fix commits/commit references from the tracer")
    return p


def main():
    args = build_parser(load_settings()).parse_args()

    out_dir = resolve(args.output_path) / ("tracer_blind" if args.blind else "tracer")
    args.cache_dir = args.cache_dir or str(resolve(args.output_path) / "tracer" / "cache")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"{args.vuln_id}.json"
    if out_json.exists() and not args.force:
        print(f"{out_json} exists; use --force to re-run")
        return

    zip_path = resolve(args.json_path) / args.ecosystem / "all.zip"
    require_zip(zip_path, args.ecosystem)
    vuln = load_vuln(zip_path, args.vuln_id)
    result = trace(args, blind(vuln) if args.blind else vuln)
    log("done")
    out_json.write_text(json.dumps(result, indent=2))
    (out_dir / f"{args.vuln_id}.md").write_text(to_markdown(result))
    print(f"{args.vuln_id}: {result['status']} -> {out_json}")


if __name__ == "__main__":
    main()
