from pydriller import Repository
import logging
import os
import glob
import pandas as pd


from configure import convert_jsonl_to_df, extract_commit_hashes,extract_file_paths,write_metric_to_file
from calc_patch_vuln_sums import calculate_total_num_vuln_hashes,calculate_patch_vuln_matches

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

import logging
import pandas as pd
from pydriller import Repository

import logging
import pandas as pd
from pydriller import Repository

def calculate_total_num_commits_between_patch_and_vulns(non_empty_vuln_hashes: pd.DataFrame) -> int:
    total_commits_between: int = 0

    for repo, patch_commit_hash, vuln_hashes in zip(non_empty_vuln_hashes["repo"], 
                                                     non_empty_vuln_hashes["patch_commit"], 
                                                     non_empty_vuln_hashes["vuln_hashes"]):
        
        repo_path: str = find_repo_path(repo)

        try:
            # Extract file paths modified in the patch commit
            patch_commit = next(Repository(repo_path, single=patch_commit_hash).traverse_commits())
            patch_files = {f.new_path or f.old_path for f in patch_commit.modified_files if (f.new_path or f.old_path)}

            for vuln_hash in vuln_hashes:
                try:
                    # Count commits affecting the same files between vuln_hash and patch_commit_hash
                    num_commits_between = sum(
                        1 for commit in Repository(repo_path, from_commit=vuln_hash, to_commit=patch_commit_hash, order='reverse').traverse_commits()
                        if any((f.new_path or f.old_path) in patch_files for f in commit.modified_files)
                    )
                    total_commits_between += num_commits_between

                except Exception as e:
                    logging.error(f"Failed to process commit range in {repo}: {e}")
        except Exception as e:
            logging.error(f"Failed to retrieve patch commit details in {repo}: {e}")

    return total_commits_between



def calculate_average_num_commits_btwn_vuln_n_patch(non_empty_vuln_hashes:pd.DataFrame,patch_vuln_matches:int, output_file: str) -> float:
    """
    Calculates the average number of commits between a patch commit and a VCC.

    Args:
        total_commits_between (int): sum of commits between every patch and its respective VCCs
        patch_vuln_matches (int): total patches that had at least one VCC

    Returns:
        float: calcuated average
    """
    total_commits_between:int = calculate_total_num_commits_between_patch_and_vulns(non_empty_vuln_hashes)
    avg_commits_btwn =  patch_vuln_matches / total_commits_between 
    
    message: str = f"The total number of commits between patches and VCCs: {total_commits_between}"
    message += f"\nAverage Number of commits Between Vulnerability and Patch: {avg_commits_btwn}"
    
    write_metric_to_file(message, output_file)

    return avg_commits_btwn



if __name__ == "__main__":
    logging.basicConfig(
        filename="production_logs/commits_btwn.log",
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )



    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/commits_btw_metrics.txt"


    patch_vuln_df = convert_jsonl_to_df(MATCH_FILES)

    logging.info("First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())
    

    # Apply functions to create new columns
    patch_vuln_df["vuln_files"] = patch_vuln_df["vuln_commits"].apply(extract_file_paths)
    patch_vuln_df["vuln_hashes"] = patch_vuln_df["vuln_commits"].apply(extract_commit_hashes)
    patch_vuln_df.drop(columns=["vuln_commits"], inplace=True)

    logging.info(" AFTER change First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())


    non_empty_vuln_hashes_df = patch_vuln_df[patch_vuln_df["vuln_hashes"].apply(lambda x: len(x) > 0)].copy()

    total_vulns = calculate_total_num_vuln_hashes(non_empty_vuln_hashes_df)
    patch_vuln_matches =  calculate_patch_vuln_matches(non_empty_vuln_hashes_df)

    calculate_average_num_commits_btwn_vuln_n_patch(non_empty_vuln_hashes_df,patch_vuln_matches, output_file)
