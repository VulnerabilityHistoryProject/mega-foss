from pydriller import Repository
import logging
import os
import glob
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

def calculate_total_num_commits_between_patch_and_vulns(non_empty_vuln_hashes: pd.DataFrame) -> int:
    
    total_commits_between: int = 0
    for repo,patch_commit_hash,vuln_hashes in zip(non_empty_vuln_hashes["repo"],non_empty_vuln_hashes["patch_commit"],non_empty_vuln_hashes["vuln_hashes"]):
        
        repo_path: str = find_repo_path(repo)
        
        for vuln_hash in vuln_hashes:
            try:
                REPOSITORY: Repository = Repository(repo_path, from_commit=vuln_hash, to_commit=patch_commit_hash, order='reverse')
                num_commits_between = sum(1 for _ in REPOSITORY.traverse_commits())
                total_commits_between += num_commits_between
            except Exception as e:
                logging.error(f"Failed to initialize repository for {repo}: {e}")
            continue

    return total_commits_between



if __name__ == "__main__":
    pass