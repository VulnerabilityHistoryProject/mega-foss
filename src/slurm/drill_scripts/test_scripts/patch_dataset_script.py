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
            vuln_dict = item.get("vuln_commit", {})
            hashes = []
            for commit_list in vuln_dict.values():
                hashes.extend(commit_list)
            return hashes
    return []

def make_cve_folder(cve_id):
    #path to pydriller-cve inside mega-foss
    pydriller_cve_dir = os.path.join(root_path, 'pydriller-cve')
    
    #path to the CVE-specific folder
    cve_folder_path = os.path.join(pydriller_cve_dir, cve_id)
    os.makedirs(cve_folder_path, exist_ok=True)
    return cve_folder_path


def clone_the_repo(repo_url,commit_hash):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    try:
        subprocess.run(["git", "clone", repo_url, placeholder_repo_folder], check=True)
        subprocess.run(["git", "checkout", commit_hash], cwd=placeholder_repo_folder, check=True)
    except subprocess.CalledProcessError as e:
        print(f"failed cloning {repo_name}: {e}")
    
def delete_cloned_repo(repo_path):
    if os.path.exists(repo_path) and os.path.isdir(repo_path):
        shutil.rmtree(repo_path)
    else:
        print(f"Wrong path: {repo_path}")

def script(vendor,product):
    cve_id = get_cve_id(vendor,product)
    print(cve_id)
    vuln_hashes = get_vuln_hashes(vendor,product)
    print(vuln_hashes)
    repo_url = get_repo_url(vendor,product)
    print(repo_url)
    #folder_path = make_cve_folder(cve_id)
    #clone_repo(repo_url,folder_path)

def get_commit_by_hash(repo_path,commit_hash,vuln_hash,output_dir):
    patch_commit = next(Repository(repo_path, single=commit_hash).traverse_commits())
    for mod in patch_commit.modified_files:
        print(f"File: {mod.filename}")
        patch_code = mod.source_code
        patch_path = os.path.join(output_dir, f"patch_{mod.filename}")
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(patch_code)
        
    vuln_commit = next(Repository(repo_path, single=vuln_hash).traverse_commits())
    for mod in vuln_commit.modified_files:
        print(f"File: {mod.filename}")
        vuln_code = mod.source_code
        vuln_path = os.path.join(output_dir, f"vuln_{mod.filename}")
        with open(vuln_path, "w", encoding="utf-8") as f:
            f.write(vuln_code)

    for mod in patch_commit.modified_files:
        print(f"Diff for {mod.filename}:")
        #print(mod.diff)
        diff_code = mod.diff
        diff_path = os.path.join(output_dir, f"diff_{mod.filename}.patch")
        with open(diff_path, "w", encoding="utf-8") as f:
            f.write(diff_code)
    
        

if __name__ == "__main__":
    
    
    repo_url = "https://github.com/jcollie/asterisk"
    patch_hash = "771b3d8749b34b6eea4e03a2e514380da9582f90"
    vuln_commit = '4bf272ae364d99dc7ca3523e6583b1ab3d4081b5'
    
    script("jcollie","asterisk")
    #print(f"[i] Cloning to: {os.path.abspath(dest_dir)}")
    #clone_the_vulnerabilities()
    # commit = get_commit_by_hash(repoooo,commit_hash)
    # for commit in Repository(repoooo, single=commit_hash).traverse_commits():
    #     print(f"Commit: {commit.hash}")
    #     for mod in commit.modified_files:
    #         print(f"Modified file: {mod.filename}")
    #         print(f"Diff: {mod.diff[:200]}...\n")
    #         print(mod.source_code_before)  # code before the commit
    #         print(mod.source_code)    
    
    # clone_the_repo(repo_url,commit_hash)
    # get_commit_by_hash('placeholder_cloned_repos/asterisk',patch_hash,vuln_commit,'pydriller-cve/CVE-2008-1897')
    # delete_cloned_repo('placeholder_cloned_repos/asterisk')
    #print(make_cve_folder('CVE-2008-1897'))