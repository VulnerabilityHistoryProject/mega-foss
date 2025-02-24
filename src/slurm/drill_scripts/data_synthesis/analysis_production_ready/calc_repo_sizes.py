import logging
import os
import glob
import pandas as pd








# Calculate repo size
def get_directory_size(path: str) -> float:
    size: float = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            size += os.path.getsize(fp)
    logging.info(f"got the size for {path} repo")
    return size
def find_repo_path(owner_repo: str, nvd_all_repos) -> str | None:
    """Finds the path of a repository inside NVD_ALL_REPOS.

    Args:
        owner_repo (str): The repository in 'owner/repo' format.

    Returns:
        str | None: The path to the repository if found, otherwise None.
    """
    
    matching_repos:list = glob.glob(os.path.join(nvd_all_repos, f"*{owner_repo}*"))
    return matching_repos[0]


def calculate_all_repo_sizes(patch_vuln_df: pd.DataFrame) -> float:
    """
    Calculates the total disk size of all unique repositories in the given DataFrame.

    This function iterates through the "repo" column, determines their local paths,
    and accumulates their sizes (in MB), ensuring each repo is counted only once.

    Args:
        patch_vuln_df (pd.DataFrame): DataFrame containing repo names.

    Returns:
        float: Total repository size in MB.
    """
    unique_repo_paths: set[str] = set()
    total_size: float = 0.0  # Initialize total size inside the function

    for repo in patch_vuln_df["repo"]:
        try:
            repo_path = find_repo_path(repo)
            if not repo_path:
                logging.warning(f"Repository path not found for {repo}, skipping.")
                continue

            if repo_path in unique_repo_paths:
                continue  # Skip if already counted

            unique_repo_paths.add(repo_path)
            repo_size: float = get_directory_size(repo_path) / (1024 * 1024)  # Convert to MB
            total_size += repo_size

            logging.info(f"Added {repo_path} ({repo_size:.2f} MB). Total: {total_size:.2f} MB")

        except Exception as e:
            logging.error(f"Error processing {repo}: {e}")
            continue  # Move to the next repo

    return total_size



if __name__ == "__main__":

    
    get_directory_size()