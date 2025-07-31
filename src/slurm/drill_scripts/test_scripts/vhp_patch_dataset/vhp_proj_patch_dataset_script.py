# For as many vulnerabilities as we know about, we need:
    # CVE identifier
    # Fix patch(s) in a file
    # Full file that was vulnerable (i.e. before the fix)
    # Full file that was fixed (i.e. after the fix)

# Data Source:
    # VHP original data (http://github.com/VulnerabilityHistoryProject/vulnerabilities/). 
    # Traverse the cves folder for every .yml file. Parse that yml and get any non-empty entries from the fixes key. 
    # That will give you the fix hash. For the original repos, just google how to get that repo cloned. 
    # Also: skip chromium (you'll thank me later...)

import os
import yaml
from pydriller import Git, RepositoryMining

# Get a list of project:repo pairs
def parse_vhp_projects(projects_path):
    projects = []
    for root, _, files in os.walk(projects_path):
        for file in files:
            with open(os.path.join(root, file), 'r') as f:
                project_data = yaml.safe_load(f)

                # Commit URL prefix and project name extraction
                if 'git_commit_url_prefix' in project_data and 'name' in project_data:
                    projects.append({
                        'name': project_data['name'],
                        'commit_prefix': project_data['git_commit_url_prefix']
                    })
                    
    return projects

# Parse CVEs in each project:repo pair and get commit hashes
def parse_cves(cve_root):
    hashes = []
    for _, _, cve in os.walk(cve_root):
        with open(os.path.join(cve_root, cve), 'r') as f:
            cve_data = yaml.safe_load(f)
            if 'fixes' in cve_data and cve_data['fixes']:
                for fix in cve_data['fixes']:
                    if 'commit' in fix and fix['commit']:
                        hashes.append(fix['commit'])

    return hashes


def main():
    # Clone vulnerabilities repo
    #
    # Retrieve commit hashes for each CVE 
    # Valid CVE files contain a field "fixes.commit" with the hash of the commit that fixed the vulnerability.
    #
    # Parse the project data
    # Using pydriller, retrieve the files affected by this commit hash, before and after the fix.
    #
    # Store the files in a folder structure like this:
    # /lists/vhp_patched_files/
    # ├── CVE-123/
    # │   ├── abcdef.patch
    # │   ├── abcdef-old/
    # │   │   └── file1.py
    # │   └── abcdef-new/
    # │       └── file1.py
    # └── CVE-456/
    #     ├── abc123.patch
    #     ├── abc123-old/
    #     │   └── file2.py
    #     └── abc123-new/
    #         └── file2.py

    cves_path = '/vulnerabilities/cves/'
    for _, cve_root, _ in os.walk(cves_path):
        print(f"Processing CVEs in {cve_root}")
    return

if __name__ == "__main__":
    main()