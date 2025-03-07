import json
import os
import subprocess
import shutil

def check_commit_exists(repo_path, commit_hash):
    """Check if a commit exists in the specified repository using git cat-file."""
    try:
        # Debug: Print the command being run
        #print(f"Running: git -C {repo_path} cat-file -e {commit_hash}")

        # Run git cat-file to check if the commit exists
        result = subprocess.run(
            ["git", "-C", repo_path, "cat-file", "commit", commit_hash],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Success: Commit {commit_hash} found in {repo_path}")
        return True
    except subprocess.CalledProcessError as e:
        # Debug: Print the error message
        #print(f"Error: {e.stderr.decode('utf-8')}")
        #print(f"Commit {commit_hash} not found in {repo_path}")
        return False

def main():
    #debugging
    print(shutil.which("git"))

    # File containing patches
    json_file = "nvdcve-github-patches.json"

    # Directory containing repositories
    repos_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../shared/rc/sfs/nvd-all-repos"))

    # Load the JSON data
    with open(json_file, "r") as file:
        patches_data = json.load(file)

    # List to store viable patches
    viable_patches = []

    # Iterate over patches
    for entry in patches_data:
        cve_id = entry.get("cve_id")
        patches = entry.get("patches", [])

        for patch in patches:
            repo_name, commit_hash = patch
            repo_path = os.path.join(repos_dir, *repo_name.split("/"))

            # Check if the repository exists in the directory
            if not os.path.isdir(repo_path):
                print(f"Error: Repository {repo_path} not found for CVE {cve_id}")
                continue

            # Check if the commit exists in the repository
            #print(f"Checking repository: {repo_path}, Commit: {commit_hash}")
            if check_commit_exists(repo_path, commit_hash):
                print(f"Success: Found commit {commit_hash} in {repo_name} for CVE {cve_id}")
                viable_patches.append({"cve_id": cve_id, "repo": repo_name, "commit": commit_hash})
            else:
                print(f"Error: Commit {commit_hash} not found in {repo_name} for CVE {cve_id}")

    # Save viable patches to a file
    with open("viable_patches.json", "w") as outfile:
        json.dump(viable_patches, outfile, indent=4)

    print(f"Viable patches saved to viable_patches.json")

if __name__ == "__main__":
    main()
