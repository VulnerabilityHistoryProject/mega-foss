import pandas as pd
import logging


def calculate_total_num_vuln_hashes(patch_vuln_df: pd.DataFrame) -> int:
    return patch_vuln_df["vuln_hashes"].explode().count()

def calculate_patch_vuln_matches(patch_vuln_df: pd.DataFrame) -> int:
    
    # Query for empty vuln_files and vuln_hashes
    empty_patch_vuln_matches_count = patch_vuln_df[
        #patch_vuln_df["vuln_files"].apply(lambda x: len(x) == 0) #& 
        patch_vuln_df["vuln_hashes"].apply(lambda x: len(x) > 0)
    ].shape[0]
    return empty_patch_vuln_matches_count



if __name__ == "__main__":


    from configure import convert_jsonl_to_df, extract_commit_hashes,extract_file_paths,write_metric_to_file
    from calc_patch_vuln_sums import calculate_total_num_vuln_hashes,calculate_patch_vuln_matches

    logging.basicConfig(
        filename="production_logs/matches_and_sums_metrics.log",
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )



    NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"
    MATCH_FILES:str = "patch_vuln_match.jsonl"
    output_file = "../analysis_calculated_metrics/matches_and_sums_metrics.txt"


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

    message = f"Total vulns {total_vulns} and total matches {patch_vuln_matches}"

    write_metric_to_file(message,output_file)