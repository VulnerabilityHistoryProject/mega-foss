import logging
from pydriller import Repository
import os
import glob
import pandas as pd






def find_repo_path(owner_repo: str, nvd_all_repos: str) -> str | None:
    """Finds the path of a repository inside NVD_ALL_REPOS.

    Args:
        owner_repo (str): The repository in 'owner/repo' format.

    Returns:
        str | None: The path to the repository if found, otherwise None.
    """
    
    matching_repos:list = glob.glob(os.path.join(nvd_all_repos, f"*{owner_repo}*"))
    return matching_repos[0]




def calculate_total_num_months_between_patch_and_vulns(non_empty_vuln_hashes: pd.DataFrame) -> int:
    total = 0

    for repo, patch_commit_hash, vuln_hashes in zip(non_empty_vuln_hashes["repo"], non_empty_vuln_hashes["patch_commit"], non_empty_vuln_hashes["vuln_hashes"]):
        
        repo_path = find_repo_path(repo)
        commits_to_analyze = [patch_commit_hash] + vuln_hashes  # Add patch commit + all vuln commits

        if not patch_commit_hash or not vuln_hashes:
            logging.warning(f"Skipping {repo} due to missing patch or vulnerability hashes.")
            continue
        
        try:    
            REPOSITORY = Repository(str(repo_path), only_commits=commits_to_analyze, order='reverse')
        except Exception as e:
            logging.error(f"Failed to initialize repository for {repo}: {e}")
            continue

        patch_commit_date = None
        total_diff_in_months = 0

        # Process commits one by one
        for commit in REPOSITORY.traverse_commits():
            if commit.hash == patch_commit_hash:
                patch_commit_date = commit.author_date  # Store patch commit date
                continue

            if patch_commit_date:
                total_diff_in_months += abs((patch_commit_date - commit.author_date).days) / 30.44  # Convert days to months
        
        total += total_diff_in_months

    return total




if __name__ == "__main__":
    calculate_total_num_months_between_patch_and_vulns()