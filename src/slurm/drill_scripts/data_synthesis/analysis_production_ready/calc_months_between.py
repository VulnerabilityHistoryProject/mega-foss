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


def calculate_total_num_months_between_patch_and_vulns(non_empty_vuln_hashes: pd.DataFrame) -> float:
    total_months_between = 0

    for repo, patch_commit_hash, vuln_hashes in zip(non_empty_vuln_hashes["repo"], non_empty_vuln_hashes["patch_commit"], non_empty_vuln_hashes["vuln_hashes"]):
        repo_path = find_repo_path(repo)

        if not patch_commit_hash or not vuln_hashes:
            logging.warning(f"Skipping {repo} due to missing patch or vulnerability hashes.")
            continue
        
        try:
            # Get patch commit to extract modified files
            patch_commit = next(Repository(repo_path, only_commits=[patch_commit_hash]).traverse_commits())
            patch_files = {f.new_path or f.old_path for f in patch_commit.modified_files}
            
            if not patch_files:
                logging.warning(f"No modified files found for patch commit {patch_commit_hash} in {repo}")
                continue
            
            patch_commit_date = patch_commit.author_date  # Store patch commit date
            
            # Iterate over vuln commits and filter by matching files
            for vuln_hash in vuln_hashes:
                vuln_commit = next(Repository(repo_path, only_commits=[vuln_hash]).traverse_commits(), None)
                
                if not vuln_commit:
                    logging.warning(f"Vuln commit {vuln_hash} not found in {repo}")
                    continue
                
                # Check if the vuln commit modifies at least one of the same files
                if any((f.new_path or f.old_path) in patch_files for f in vuln_commit.modified_files):
                    diff_in_months = abs((patch_commit_date - vuln_commit.author_date).days) / 30.44  # Convert days to months
                    total_months_between += diff_in_months

        except Exception as e:
            logging.error(f"Failed to process repository {repo}: {e}")
            continue

    return total_months_between

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