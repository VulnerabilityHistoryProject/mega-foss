import json
import os
import glob
import logging
from pydriller import Git
import sys

# Base directory where repositories are stored
NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"

# JSON file with all CVEs, patch hashes, and source FOSS projects
PATCH_HASHES = "../viable_patches.json"

# Output JSON file
PROCESSED_JSON = "test_patch_vuln_match.json"

# Base name for log file and log directory
LOG_DIR = "test_logs"
LOG_FILE_BASE = "test_drill.log"

# Make sure the log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Full path to the log file
log_file = os.path.join(LOG_DIR, LOG_FILE_BASE)
counter = 1


while os.path.exists(log_file):
    log_file = f"test_drill{counter}.log"
    counter += 1

# Configure logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def safe_load_json(filepath):
    """Safely loads JSON data from a file, returning an empty list if the file doesn't exist or is invalid."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Error reading {filepath}: {e}")
        return []
    

def convert_sets_to_lists(obj):
    """Recursively convert sets to lists in a nested structure."""
    if isinstance(obj, set):
        return list(obj)  # Convert set to list
    elif isinstance(obj, dict):
        return {key: convert_sets_to_lists(value) for key, value in obj.items()}  # Recurse for dictionary values
    elif isinstance(obj, list):
        return [convert_sets_to_lists(item) for item in obj]  # Recurse for list items
    else:
        return obj  # Return the object if it's neither a set, list, nor dict


def main():
    """Main function to process CVEs and extract vulnerability-inducing commits."""

    # Load JSON data
    cve_data = safe_load_json(PATCH_HASHES)

   
    # Process only the first 10 entries in the JSON for debugging
    for entry in cve_data[:50]:
            
        try:
            cve_id = entry["cve_id"]
            repo_name = entry["repo"]
            commit_hash = entry["commit"]

            # Search for the repository in the directory
            repo_path_variants = [
                repo_name,
                repo_name.replace("/", "_"),
                repo_name.replace("/", "-"),
            ]

            matching_repos = []
            for variant in repo_path_variants:
                matching_repos += glob.glob(os.path.join(NVD_ALL_REPOS, f"*{variant}*"))

            if not matching_repos:
                logging.warning(f"Repo not found for {repo_name}. Skipping...")
                continue

            repo_path = matching_repos[0]  # Assume the first match is correct

            # Analyze the Git repository
            git_repo = Git(repo_path)

            try:
                patch_commit = git_repo.get_commit(commit_hash)
            except Exception as e:
                logging.error(f"Error retrieving commit {commit_hash} in {repo_name}: {e}")
                continue

            try:
                results = git_repo.get_commits_last_modified_lines(patch_commit)
            except Exception as e:
                logging.error(f"Error processing patch commit {commit_hash}: {e}")
                continue

            # Store the processed result
            processed_entry = {
                "cve_id": cve_id,
                "repo": repo_name,
                "patch_commit": commit_hash,
                "vuln_commit": convert_sets_to_lists(results),  # Convert set to list
            }

            # Write to JSONL
            with open(PROCESSED_JSON, "a") as file:  # Use "a" mode to append
                file.write(json.dumps(processed_entry) + "\n")  # Dump as a single line

            logging.info(f"Processed {commit_hash} successfully.")


        except Exception as e:
            logging.error(f"Unexpected error processing {entry}: {e}")
            continue


if __name__ == "__main__":
    main()
