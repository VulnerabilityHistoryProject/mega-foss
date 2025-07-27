from pydriller import Repository
import subprocess
import json

repo_url = "https://github.com/jcollie/asterisk"
commit_hash = "771b3d8749b34b6eea4e03a2e514380da9582f90"  # Example hash
repo_name = repo_url.split("/")[-1].replace(".git", "")
dest_dir = f"cloned/{repo_name}"

with open('src/slurm/drill_scripts/test_scripts/test_patch_vuln_match.json', 'r') as file:
    data = json.load(file)
    #print(data)

def get_cve_id(vendor,product):
    repo_name = vendor+"/"+product
    for item in data:
        if item["repo"] == repo_name:
            return item["cve_id"]
    return None

def clone_the_vulnerabilities():
    try:
        subprocess.run(["git", "clone", repo_url, dest_dir], check=True)
        subprocess.run(["git", "checkout", commit_hash], cwd=dest_dir, check=True)
        print(f"[✓] Cloned and checked out {repo_name} at {commit_hash}")
    except subprocess.CalledProcessError as e:
        print(f"[X] Failed for {repo_name}: {e}")
        

if __name__ == "__main__":
    print(get_cve_id("jcollie","asterisk"))