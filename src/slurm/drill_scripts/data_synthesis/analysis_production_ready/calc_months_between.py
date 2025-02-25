import logging
from pydriller import Repository
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

def calculate_average_num_months_btwn(patch_vuln_matches: int, non_empty_vuln_hashes:pd.DataFrame, output_file:str) -> float:
    """
    Calculates the average number of months between a patch commit and a VCC

    Args:
        total_months_between (int): sum of months between every patch and its respective VCCs
        patch_vuln_matches (int): total patches that had at least one VCC

    Returns:
        float: calculated average
    """
    total_months_between  = calculate_total_num_months_between_patch_and_vulns(non_empty_vuln_hashes)
    avg_months_btwn =  patch_vuln_matches / total_months_between 
    message: str = f"The total number of months between commits: {total_months_between}"
    message += f"\nAverage Number of Months Between Vulnerability and Patch: {avg_months_btwn}"
    write_metric_to_file(message,output_file)
    return avg_months_btwn


if __name__ == "__main__":

    from configure import convert_jsonl_to_df, extract_commit_hashes,extract_file_paths,write_metric_to_file
    from calc_patch_vuln_sums import calculate_patch_vuln_matches

    logging.basicConfig(
        filename="production_logs/months_btwn.log",
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )



    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/months_btw_metrics.txt"


    patch_vuln_df = convert_jsonl_to_df(MATCH_FILES)

    logging.info("First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())
    

    # Apply functions to create new columns
    patch_vuln_df["vuln_files"] = patch_vuln_df["vuln_commits"].apply(extract_file_paths)
    patch_vuln_df["vuln_hashes"] = patch_vuln_df["vuln_commits"].apply(extract_commit_hashes)
    patch_vuln_df.drop(columns=["vuln_commits"], inplace=True)

    logging.info(" AFTER change First 5 rows of the DataFrame:\n%s", patch_vuln_df.head().to_string())


    non_empty_vuln_hashes_df = patch_vuln_df[patch_vuln_df["vuln_hashes"].apply(lambda x: len(x) > 0)].copy()

    patch_vuln_matches =  calculate_patch_vuln_matches(non_empty_vuln_hashes_df)

    calculate_average_num_months_btwn(patch_vuln_matches,non_empty_vuln_hashes_df,output_file)