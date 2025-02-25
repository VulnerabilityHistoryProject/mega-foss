import os, glob
import logging 
from pydriller import Repository

import pandas as pd


def find_repo_path(owner_repo: str) -> str | None:
    """Finds the path of a repository inside NVD_ALL_REPOS.

    Args:
        owner_repo (str): The repository in 'owner/repo' format.

    Returns:
        str | None: The path to the repository if found, otherwise None.
    """
    nvd_all_repos = "/shared/rc/sfs/nvd-all-repos"
    matching_repos:list = glob.glob(os.path.join(nvd_all_repos, f"*{owner_repo}*"))
    return matching_repos[0]

def calculate_num_vulns_made_and_fixed_by_same_person(non_empty_vuln_hashes: pd.DataFrame)->int:
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

        commit = next(Repository(repo_path, single=patch_commit_hash).traverse_commits())
        patch_commit_author = commit.author.email

        occurances: int = 0

        # Process commits one by one
        for commit in REPOSITORY.traverse_commits():
            if commit.author.email == patch_commit_author:
                occurances += 1


        total += occurances

    return total

if __name__ == "__main__":
    calculate_num_vulns_made_and_fixed_by_same_person()