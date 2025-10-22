import csv
import subprocess
from pathlib import Path

def run(cmd, cwd=None):
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
    output = run(f"git diff --name-only {old_commit} {new_commit}", cwd=repo)
    if output:
        return output.splitlines()
    else:
        return []

def get_patch(repo, old_commit, new_commit):
    return run(f"git diff {old_commit} {new_commit}", cwd=repo)

def get_file_content(repo, commit, file_path):
    return run(f"git show {commit}:{file_path}", cwd=repo)

def process_cve(cve, repo, commit, out_root):
    cve_dir = out_root + "/" + cve
    Path(cve_dir).mkdir(parents=True, exist_ok=True)

    parent = get_parent(repo, commit)
    changed_files = get_changed_files(repo, parent, commit)

    patch_content = get_patch(repo, parent, commit)
    patch_file = cve_dir + "/" + commit + ".patch"
    Path(patch_file).write_text(patch_content)

    old_dir = cve_dir + "/" + commit + "-old"
    new_dir = cve_dir + "/" + commit + "-new"
    Path(old_dir).mkdir(exist_ok=True)
    Path(new_dir).mkdir(exist_ok=True)

    for file_path in changed_files:
        if file_path.lower().endswith(".md"):
            continue

        old_content = get_file_content(repo, parent, file_path)
        new_content = get_file_content(repo, commit, file_path)

        name = Path(file_path).stem + ".py"

        if old_content:
            Path(old_dir + "/" + name).write_text(f'"""{old_content}"""')
        if new_content:
            Path(new_dir + "/" + name).write_text(f'"""{new_content}"""')

    print(f"Generated files for CVE {cve}")

def main():
    root = str(Path(__file__).parent.resolve())
    csv_path = root + "/output/repos_match_cve.csv"
    repos_root = str(Path(root).parent) + "/mega-foss-repos"
    out_root = str(Path(root).parent) + "/mega-foss-historic"
    Path(out_root).mkdir(exist_ok=True)

    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                repo_name = row["github repo"].split("/")[-1]
                repo = repos_root + "/" + repo_name
                cves = row["cve ids"].split()

                for cve in cves:
                    commits = get_commits(repo, cve)
                    if not commits:
                        continue
                    process_cve(cve, repo, commits[0], out_root)
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")

if __name__ == "__main__":
    main()
