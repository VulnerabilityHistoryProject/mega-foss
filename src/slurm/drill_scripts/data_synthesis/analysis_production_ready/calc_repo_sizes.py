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

    from configure import convert_jsonl_to_df, extract_commit_hashes,extract_file_paths,write_metric_to_file

    logging.basicConfig(
        filename="production_logs/repo_sizes.log",
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )



    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/repo_sizes.txt"


    patch_vuln_df = convert_jsonl_to_df(MATCH_FILES)

    logging.info("First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())
    

    # Apply functions to create new columns
    patch_vuln_df["vuln_files"] = patch_vuln_df["vuln_commits"].apply(extract_file_paths)
    patch_vuln_df["vuln_hashes"] = patch_vuln_df["vuln_commits"].apply(extract_commit_hashes)
    patch_vuln_df.drop(columns=["vuln_commits"], inplace=True)

    logging.info(" AFTER change First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())


    non_empty_vuln_hashes_df = patch_vuln_df[patch_vuln_df["vuln_hashes"].apply(lambda x: len(x) > 0)].copy()

    # total_vulns = calculate_total_num_vuln_hashes(non_empty_vuln_hashes_df)
    # patch_vuln_matches =  calculate_patch_vuln_matches(non_empty_vuln_hashes_df)

    total_size = calculate_all_repo_sizes(non_empty_vuln_hashes_df)
    message = f"The total size of all the repos in MB is {total_size}MB"
    write_metric_to_file(message,output_file)
    