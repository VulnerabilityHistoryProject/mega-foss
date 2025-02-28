import pandas as pd
import logging
import jsonlines




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

def write_metric_to_file(message:str, output_file)-> None:
    
    with open(output_file,"a") as file:
        file.write(message + '\n')


def extract_file_paths(vuln_commits):
    try:
        if isinstance(vuln_commits, dict):
            return list(vuln_commits.keys())
        return []
    except Exception as e:
        print(f"Error extracting file paths: {e}")
        return []
def extract_commit_hashes(vuln_commits):
    try:
        if isinstance(vuln_commits, dict):
            return list({commit for commits in vuln_commits.values() if isinstance(commits, list) for commit in commits})
        return []
    except Exception as e:
        print(f"Error extracting commit hashes: {e}")
        return []

if __name__ == "__main__":
    convert_jsonl_to_df()