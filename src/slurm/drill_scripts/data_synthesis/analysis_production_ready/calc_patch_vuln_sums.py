import pandas as pd



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
    calculate_patch_vuln_matches()
    calculate_total_num_vuln_hashes()