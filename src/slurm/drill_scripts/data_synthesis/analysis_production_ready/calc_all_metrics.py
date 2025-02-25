import logging
import pandas as pd
import jsonlines    
from enum import Enum


from calc_repo_sizes import calculate_all_repo_sizes
from calc_commits_between import calculate_total_num_commits_between_patch_and_vulns
from calc_months_between import calculate_total_num_months_between_patch_and_vulns
from calc_same_author import calculate_num_vulns_made_and_fixed_by_same_person
class Metric(Enum):
    """

    Obtaining ...

    1. Total size of the cloned repos
    2. Total number of vulnerability inducing commits (vuln commits) found & (& num of patches missing a vuln (not found))
    3. Average number of months between vuln commit and patch commit (or fix)
    4. Average number of commits between the vuln commit & patch commit (or fix)
    5. Average number of vuln commits fixed by patch commit (or fix)
    6. Percentage of vulns where the vuln commit and fix were made by the same person

    Args:
        Enum (_type_): identifies for the metric being calculated
    """
    
    TOTAL_SIZE = 1
    TOTAL_NUM_VCC = 2
    AVG_NUM_MONTHS_BTWN = 3
    AVG_NUM_COMMITS_BTWN = 4
    AVG_NUM_VCC_FXD_BY_PATCH = 5
    PERCENT_OF_VCC_N_PATCH_MADE_BY_SAME = 6


def convert_jsonl_to_df(json_path: str) -> pd.DataFrame:
    """Converts a JSONL file to a pandas DataFrame with error handling."""
    
    data: list[object] = []
    
    try:
        with jsonlines.open(json_path) as reader:
            data = [entry for entry in reader]

        # Convert the list of dictionaries into a pandas DataFrame
        patch_vuln_df = pd.DataFrame(data)
        logging.info(f"Successfully converted {json_path} to DataFrame with {len(patch_vuln_df)} rows.")

        return patch_vuln_df

    except FileNotFoundError:
        logging.error(f"File not found: {json_path}")
    except jsonlines.jsonlines.Error as e:
        logging.error(f"Error reading JSONL file {json_path}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while processing {json_path}: {e}")

    return pd.DataFrame()  # Return an empty DataFrame in case of failure

def calculate_total_size(patch_vuln_df: pd.DataFrame) -> float:
    
    size: float = calculate_all_repo_sizes(patch_vuln_df)
    
    message: str = f"Size of all cloned repos: {size}"

    write_metric_to_file(message)
    return size
    
def calculate_patches_without_vcc(total_entries: int, patch_vuln_matches: int) -> int:
    missing: int = total_entries - patch_vuln_matches
    message = f"Total patch vuln mathes (patches with at least 1 VCC) : {patch_vuln_matches}"
    message += f"\n{missing} patch commits don't have at least 1 VCC"
    write_metric_to_file(message)
    return missing

def calculate_average_num_months_btwn(patch_vuln_matches: int, non_empty_vuln_hashes:pd.DataFrame) -> float:
    """
    Calculates the average number of months between a patch commit and a VCC

    Args:
        total_months_between (int): sum of months between every patch and its respective VCCs
        patch_vuln_matches (int): total patches that had at least one VCC

    Returns:
        float: calculated average
    """
    total_months_between  = calculate_total_num_months_between_patch_and_vulns(non_empty_vuln_hashes)
    avg_months_btwn =  total_months_between / patch_vuln_matches
    message: str = f"The total number of months between commits: {total_months_between}"
    message += f"\nAverage Number of Months Between Vulnerability and Patch: {avg_months_btwn}"
    write_metric_to_file(message)
    return avg_months_btwn

def calculate_average_num_commits_btwn_vuln_n_patch(non_empty_vuln_hashes:pd.DataFrame,patch_vuln_matches:int) -> float:
    """
    Calculates the average number of commits between a patch commit and a VCC.

    Args:
        total_commits_between (int): sum of commits between every patch and its respective VCCs
        patch_vuln_matches (int): total patches that had at least one VCC

    Returns:
        float: calcuated average
    """
    total_commits_between:int = calculate_total_num_commits_between_patch_and_vulns(non_empty_vuln_hashes)
    avg_commits_btwn = total_commits_between / patch_vuln_matches
    
    message: str = f"The total number of commits between patches and VCCs: {total_commits_between}"
    message += f"\nAverage Number of Months Between Vulnerability and Patch: {avg_commits_btwn}"
    write_metric_to_file(message)
    return avg_commits_btwn

def calculate_average_num_vuln_commits_fixed_by_patch_commit(
        total_vulns,patch_vuln_matches) -> float:
    avg_num_VCC_fxd_by_ptach = total_vulns / patch_vuln_matches


    message: str = f"Average number of VCCs fixed by a single patch commit {avg_num_VCC_fxd_by_ptach}"
    write_metric_to_file(message)
    return avg_num_VCC_fxd_by_ptach

def calculate_percent_of_vcc_n_patch_w_same_author(total_vulns: int , num_by_same_author: int)-> float:
    
    percent_of_vcc_n_patch_with_same_auth = calculate_num_vulns_made_and_fixed_by_same_person(non_empty_vuln_hashes:pd.DataFrame)
    
    message: str = f"The total number of commits between patches and VCCs: {percent_of_vcc_n_patch_with_same_auth}"
    message += f"\nAverage Number of Months Between Vulnerability and Patch: {percent_of_vcc_n_patch_with_same_auth}"
    write_metric_to_file(message)
    return percent_of_vcc_n_patch_with_same_auth


def write_metric_to_file(message:str, output_file: str)-> None:

    with open(output_file,"a") as file:
        file.write(message + '\n')


if __name__ == "__main__":
    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "../production_ready/patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/metrics.txt"

    patch_vuln_df = convert_jsonl_to_df(MATCH_FILES)