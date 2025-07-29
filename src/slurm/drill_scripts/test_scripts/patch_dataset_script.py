import os
import sys
import shutil
module_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
root_path = os.path.abspath(os.path.join(module_path, '..'))

if module_path not in sys.path:
    sys.path.append(module_path)


from pydriller import Repository
import subprocess
import json


from cve.graphql.make_gql_queries import get_repo_url

with open('src/slurm/drill_scripts/test_scripts/test_patch_vuln_match.json', 'r') as file:
    data = json.load(file)

placeholder_repo_folder = "placeholder_cloned_repos"
"""
   Checklist:
   User enters vendor and product
   The script needs to:
        Get the repo url
        Get the cve id
        Clone the repo in the temporary folder 
        Used pydriller on the cloned repo and output the results in a folder named after the cve_id
        Same with the new
        Use pydriller to get the diff file
        
    Repeat 
"""

def get_cve_id(vendor,product):
    repo_name =  f"{vendor}/{product}"
    for item in data:
        if item["repo"] == repo_name:
            return item["cve_id"]
    return None

def get_vuln_hashes(vendor, product):
    repo_name = f"{vendor}/{product}"
    for item in data:
        if item["repo"] == repo_name:
            return item.get("vuln_commit", {})
    return {}

def make_cve_folder(cve_id):
    #path to pydriller-cve inside mega-foss
    pydriller_cve_dir = os.path.join(root_path, 'pydriller-cve')
    
    #path to the CVE-specific folder
    cve_folder_path = os.path.join(pydriller_cve_dir, cve_id)
    os.makedirs(cve_folder_path, exist_ok=True)
    return cve_folder_path


def clone_the_repo(repo_url):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    try:
        subprocess.run(["git", "clone", repo_url, placeholder_repo_folder], check=True)
        #subprocess.run(["git", "checkout", commit_hash], cwd=placeholder_repo_folder, check=True)
    except subprocess.CalledProcessError as e:
        print(f"failed cloning {repo_name}: {e}")
    
def delete_cloned_repo(repo_path):
    if os.path.exists(repo_path) and os.path.isdir(repo_path):
        shutil.rmtree(repo_path)
    else:
        print(f"Wrong path: {repo_path}")

def script(vendor,product):
    cve_id = get_cve_id(vendor,product)
    vuln_hashes = get_vuln_hashes(vendor,product)
    repo_url = get_repo_url(vendor,product)
    folder_path = make_cve_folder(cve_id)
    clone_the_repo(repo_url)
    get_commit_by_hash(placeholder_repo_folder,"771b3d8749b34b6eea4e03a2e514380da9582f90",vuln_hashes,folder_path)
    delete_cloned_repo(placeholder_repo_folder)

def get_commit_by_hash(repo_path, patch_hash, vuln_commit_dict, output_dir):
    patch_commit = next(Repository(repo_path, single=patch_hash).traverse_commits())
    
    for mod in patch_commit.modified_files:
        print(f"Patch File: {mod.filename}")
        patch_code = mod.source_code or ""
        patch_path = os.path.join(output_dir, f"patch_{mod.filename}")
        os.makedirs(os.path.dirname(patch_path), exist_ok=True)
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(patch_code)

    # Loop through all vuln commits
    for filename, commit_hashes in vuln_commit_dict.items():
        for i, commit_hash in enumerate(commit_hashes):
            try:
                commit = next(Repository(repo_path, single=commit_hash).traverse_commits())
                for mod in commit.modified_files:
                    if mod.filename.endswith(filename.split("/")[-1]):  
                        print(f"Vuln File: {mod.filename}")
                        vuln_code = mod.source_code or ""
                        vuln_path = os.path.join(output_dir, f"vuln_{i}_{mod.filename}")
                        os.makedirs(os.path.dirname(vuln_path), exist_ok=True)
                        with open(vuln_path, "w", encoding="utf-8") as f:
                            f.write(vuln_code)
            except StopIteration:
                print(f"Could not find commit {commit_hash}")

    for mod in patch_commit.modified_files:
        print(f"Diff for {mod.filename}")
        diff_code = mod.diff or ""
        diff_path = os.path.join(output_dir, f"diff_{mod.filename}.patch")
        os.makedirs(os.path.dirname(diff_path), exist_ok=True)
        with open(diff_path, "w", encoding="utf-8") as f:
            f.write(diff_code)
    
        

if __name__ == "__main__":

    script("jcollie","asterisk")
    
    