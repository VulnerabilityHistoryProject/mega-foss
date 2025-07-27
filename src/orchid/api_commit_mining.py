import subprocess
import tempfile
import shutil
from pathlib import Path
import sys
import json

def get_commits_with_tags(repo_url, branch='main'):
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_name = Path(repo_url).stem + '.git'
        repo_path = Path(tmpdir) / repo_name

        # Clone the repo
        subprocess.run(
    ['git', 'clone', '--bare', '--depth', '100', '--branch', branch, repo_url, str(repo_path)],
    capture_output=True,
    text=True,
    timeout=60
)

        def git_cmd(args):
            return subprocess.run(['git', '--git-dir', str(repo_path)] + args,
                                  capture_output=True, text=True)

        commits = git_cmd(['rev-list', branch])
        commits = commits.stdout.strip().splitlines()

        results = []
        for commit in commits:
            tag = git_cmd(['describe', '--tags', '--abbrev=0', commit])
            if tag.returncode != 0:
                continue
            message = git_cmd(['show', '-s', '--format=%s', commit])
            results.append({
                'commit': commit,
                'message': message.stdout.strip(),
                'tag': tag.stdout.strip()
            })
        return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python git_tags.py <repo_url> [branch]")
        sys.exit(1)

    repo = sys.argv[1]
    branch = sys.argv[2] if len(sys.argv) > 2 else "main"

    output = get_commits_with_tags(repo, branch)
    print(json.dumps(output, indent=2))
