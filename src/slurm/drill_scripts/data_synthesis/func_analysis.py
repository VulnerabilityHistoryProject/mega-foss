import logging
import jsonlines
import pandas as pd
from slurm.drill_scripts.data_synthesis.test_analysis import analyze_patch_vuln_data

def setup_logger():
    """Sets up the logger to write to analysis.log"""
    logging.basicConfig(
        filename="analysis.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def load_data(json_path: str) -> pd.DataFrame:
    """Loads data from a JSONL file into a pandas DataFrame."""
    try:
        data = []
        with jsonlines.open(json_path) as reader:
            data = [entry for entry in reader]
        df = pd.DataFrame(data)
    except Exception as e:
        logging.error(f"Failed to load data from {json_path}: {e}")
        raise
    return df

def extract_vuln_files_commits(vuln_commits):
    """Extracts file paths and commit hashes from vulnerability commits."""
    if vuln_commits:
        files = list(vuln_commits.keys())
        commits = [commit for commits in vuln_commits.values() for commit in commits]
        return pd.Series([files, commits])
    return pd.Series([[], []])

def main():
    setup_logger()
    logging.info("Starting analysis process")
    
    json_path = "../production_ready/patch_vuln_match.jsonl"
    patch_vuln_df = load_data(json_path)
    
    # Apply transformation to extract vuln files and commits
    patch_vuln_df[['vuln_files', 'vuln_commits']] = patch_vuln_df['vuln_commits'].apply(extract_vuln_files_commits)
    
    # Call the analysis function
    analyze_patch_vuln_data(patch_vuln_df)
    
    logging.info("Analysis process completed successfully")

if __name__ == "__main__":
    main()
