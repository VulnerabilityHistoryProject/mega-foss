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


def calculate_percent_of_vcc_n_patch_w_same_author(total_vulns: int, non_empty_vuln_hashes:pd.DataFrame, output_file: str)-> float:

    num_by_same_author: int = calculate_num_vulns_made_and_fixed_by_same_person(non_empty_vuln_hashes)
    
    percent_of_vcc_n_patch_with_same_auth = num_by_same_author / total_vulns 
    
    message: str = f" Total number of vulns patched by same author {num_by_same_author}"
    message += f"\nPercentage of Vulnerabilities and Patches by the Same Person{percent_of_vcc_n_patch_with_same_auth}"
    write_metric_to_file(message, output_file)
    return percent_of_vcc_n_patch_with_same_auth

if __name__ == "__main__":
    from configure import convert_jsonl_to_df, extract_commit_hashes,extract_file_paths,write_metric_to_file
    from calc_patch_vuln_sums import calculate_total_num_vuln_hashes,calculate_patch_vuln_matches

    logging.basicConfig(
        filename="production_logs/same_author.log",
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )



    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/same_author.txt"


    patch_vuln_df = convert_jsonl_to_df(MATCH_FILES)

    logging.info("First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())
    

    # Apply functions to create new columns
    patch_vuln_df["vuln_files"] = patch_vuln_df["vuln_commits"].apply(extract_file_paths)
    patch_vuln_df["vuln_hashes"] = patch_vuln_df["vuln_commits"].apply(extract_commit_hashes)
    patch_vuln_df.drop(columns=["vuln_commits"], inplace=True)

    logging.info(" AFTER change First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())


    non_empty_vuln_hashes_df = patch_vuln_df[patch_vuln_df["vuln_hashes"].apply(lambda x: len(x) > 0)].copy()

    total_vulns = calculate_total_num_vuln_hashes(non_empty_vuln_hashes_df)

    calculate_percent_of_vcc_n_patch_w_same_author(total_vulns,non_empty_vuln_hashes_df,output_file)