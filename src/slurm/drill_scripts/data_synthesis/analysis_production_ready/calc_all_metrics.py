import logging
import pandas as pd
import jsonlines    
from enum import Enum



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

def calculate_average_num_vuln_commits_fixed_by_patch_commit(
        total_vulns,patch_vuln_matches) -> float:
    return total_vulns / patch_vuln_matches

def calculate_patch_commits_missing_vcc(total_entires:int, total_num_vcc: int) -> int:
    """
    Calculates the number of commits that didn't have at least one associated 
    VCC (vulnerable contributing commit)

    Returns:
        int: the number of commits found that fit this condition
    """
    return total_entires - total_num_vcc

def calculate_average_num_months_btwn(total_months_between:int , patch_vuln_matches: int) -> float:
    """
    Calculate the average number of monoths between a patch commit and a VCC

    Args:
        total_months_between (int): sum of months between every patch and its respective VCCs
        patch_vuln_matches (int): total patches that had at least one VCC

    Returns:
        float: calculated average
    """
 
    return total_months_between / patch_vuln_matches
def write_metric_to_file(metric, output_file: str)-> None:

    with open(output_file,"a") as file:
        file.write(f"")


if __name__ == "__main__":


    convert_jsonl_to_df()