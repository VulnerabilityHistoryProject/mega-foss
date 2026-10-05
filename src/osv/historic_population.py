import csv
import subprocess
from pathlib import Path

VALID_EXTENSIONS = {".c", ".cpp", ".h", ".hpp", ".java", ".cs"}

def run(cmd, cwd=None):
    if cwd is not None:
        cwd = str(cwd)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        return ""

def get_commits(repo, cve):
    output = run(f'git log --all --grep="{cve}" --pretty=format:%H', cwd=repo)
    if output:
        return output.splitlines()
    else:
        return []

def get_parent(repo, commit):
    parts = run(f"git rev-list --parents -n 1 {commit}", cwd=repo).split()
    if len(parts) > 1:
        return parts[1]
    else:
        return ""

def get_changed_files(repo, old_commit, new_commit):
    patterns_list = []

    for ext in VALID_EXTENSIONS:
        patterns_list.append(f"*{ext}")
    patterns = ' '.join(patterns_list)

    output = run(f"git diff --name-only {old_commit} {new_commit} -- {patterns}", cwd=repo)
    if output:
        return output.splitlines()
    else:
        return []

def get_patch(repo, old_commit, new_commit):
    return run(f"git diff {old_commit} {new_commit}", cwd=repo)

def get_file_content(repo, commit, file_path):
    return run(f"git show {commit}:{file_path}", cwd=repo)

def get_commit_message(repo, commit):
    return run(f'git log -n 1 --pretty=%B {commit}', cwd=repo).strip()

def process_cve(cve, repo, commit, out_root):
    parent = get_parent(repo, commit)
    changed_files = get_changed_files(repo, parent, commit)

    if not changed_files:
        return

    cve_dir = out_root + "/" + cve
    Path(cve_dir).mkdir(parents=True, exist_ok=True)

    patch_content = get_patch(repo, parent, commit)
    patch_file = cve_dir + "/" + commit + ".patch"
    Path(patch_file).write_text(patch_content)

    old_dir = cve_dir + "/" + commit + "-old"
    new_dir = cve_dir + "/" + commit + "-new"
    Path(old_dir).mkdir(exist_ok=True)
    Path(new_dir).mkdir(exist_ok=True)
    
    commit_message = get_commit_message(repo, commit)

    message_file = cve_dir + "/" + commit + ".message.txt"
    Path(message_file).write_text(commit_message)

    for file_path in changed_files:
        extension = Path(file_path).suffix
        name = Path(file_path).stem + extension

        old_content = get_file_content(repo, parent, file_path)
        new_content = get_file_content(repo, commit, file_path)

        if old_content:
            Path(old_dir + "/" + name).write_text(old_content)
        if new_content:
            Path(new_dir + "/" + name).write_text(new_content)

    print(f"Generated files for CVE {cve}")

def main():
    root = Path(__file__).parent.resolve()
    csv_path = root / "output/repos_match_cve.csv"
    repos_root = root.parent / "mega-foss-repos"
    out_root = root.parent / "mega-foss-historic"
    out_root.mkdir(exist_ok=True)

    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                repo_name = row["github repo"].split("/")[-1]
                repo = (repos_root / repo_name).resolve()
                repo_str = str(repo)

                if not repo.exists():
                    print(f"Repo does not exist, skipping: {repo_str}")
                    continue

                cves = row["cve ids"].split()

                for cve in cves:
                    commits = get_commits(repo_str, cve)
                    if not commits:
                        continue
                    process_cve(cve, repo_str, commits[0], str(out_root))
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")

if __name__ == "__main__":
    main()
