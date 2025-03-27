
import logging
import pandas as pd
import jsonlines    

import os
import sys
import glob
from pydriller import Repository, Commit
from datetime import datetime
from dateutil.relativedelta import relativedelta
from typing import Optional

from pathlib import Path

"""
    Obtaining ...

    1. Total size of the cloned repos
    2. Total number of vulnerability inducing commits (vuln commits) found & (& num of patches missing a vuln (not found))
    3. Average number of months between vuln commit and patch commit (or fix)
    4. Average number of commits between the vuln commit & patch commit (or fix)
    5. Average number of vuln commits fixed by patch commit (or fix)
    6. Percentage of vulns where the vuln commit and fix were made by the same person
    """


# Configure logging
logging.basicConfig(
filename="py_logs/analysis5.log",
level=logging.WARNING,
format="%(asctime)s - %(levelname)s - %(message)s",
)


NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"

MATCH_FILES:str = "../production_ready/patch_vuln_match.jsonl"

### Point 1
SIZE_OF_ALL_CLONED_REPOS: float = 0 ### size in MB

### Point 2
TOTAL_VULNS: int = 0 ### Another way to say this is total patch vuln pairs
TOTAL_PATCH_COMMITS_W_VULN_COMMIT: int = 0


### Point 6
### I can get the the number of patches without vulns / not found by doing total entires - total vulns
BY_SAME_PERSON: int = 0 ### Num of vulns made by the same person
PERCENTAGE_OF_VULN_N_PATCH_BY_SAME_PERSON: float = 0.0


### Point 3
TOTAL_NUM_MONTHS_BETWEEN: int = 0
AVERAGE_NUM_MONTHS_BETWEEN_VULN_N_PATCH: float = 0.0

### Point 4
TOTAL_NUM_COMMITS_BETWEEN: int = 0
AVERAGE_NUM_COMMITS_BETWEEN_VULN_N_PATCH: float = 0.0



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


# Calculate repo size
def get_directory_size(path: str) -> float:
    size: float = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            size += os.path.getsize(fp)
    logging.info(f"got the size for {path} repo")
    return size


def extract_vuln_files_commits(vuln_commits):
    if isinstance(vuln_commits, dict):  # Ensure it's a dictionary
        files = list(vuln_commits.keys())
        commits = [commit for commit_list in vuln_commits.values() for commit in commit_list]
        return pd.Series([files, commits])
    else:
        return pd.Series([[], []])  # Return empty lists if invalid
    
def safe_extract_vuln_files_commits(vuln_commits):
    """Wrapper function for error handling and logging."""
    try:
        return extract_vuln_files_commits(vuln_commits)
    except Exception as e:
        logging.error(f"Error processing vuln_commits: {vuln_commits} - {e}", exc_info=True)
        return pd.Series([[], []])  # Return empty lists in case of failure



def extract_file_paths(vuln_commits):
    try:
        if isinstance(vuln_commits, dict):
            return list(vuln_commits.keys())
        return []
    except Exception as e:
        print(f"Error extracting file paths: {e}")
        return []

# Function to extract commit hashes with error handling
def extract_commit_hashes(vuln_commits):
    try:
        if isinstance(vuln_commits, dict):
            return list({commit for commits in vuln_commits.values() if isinstance(commits, list) for commit in commits})
        return []
    except Exception as e:
        print(f"Error extracting commit hashes: {e}")
        return []




def find_repo_path(owner_repo: str) -> str | None:
    """Finds the path of a repository inside NVD_ALL_REPOS.

    Args:
        owner_repo (str): The repository in 'owner/repo' format.

    Returns:
        str | None: The path to the repository if found, otherwise None.
    """
    # try:
    #     if not NVD_ALL_REPOS.exists() or not NVD_ALL_REPOS.is_dir():
    #         logging.error(f"NVD_ALL_REPOS path {NVD_ALL_REPOS} does not exist or is not a directory.")
    #         return None

    #     for repo in NVD_ALL_REPOS.iterdir():
    #         if owner_repo in repo.name:
    #             logging.info(f"Found repository path for {owner_repo}: {repo}")
    #             return str(repo)

    #     logging.warning(f"Repo not found for {owner_repo}. Skipping...")
    #     return None

    # except Exception as e:
    #     logging.critical(f"Error while searching for repo path {owner_repo}: {e}", exc_info=True)
    #     return None
    matching_repos:list = glob.glob(os.path.join(NVD_ALL_REPOS, f"*{owner_repo}*"))
    return matching_repos[0]


# Assuming Repository is defined earlier and other variables exist globally
def iterate_and_calculate(patch_vuln_df: pd.DataFrame):
    global NVD_ALL_REPOS, TOTAL_PATCH_COMMITS_W_VULN_COMMIT, TOTAL_NUM_MONTHS_BETWEEN, TOTAL_NUM_COMMITS_BETWEEN, BY_SAME_PERSON, SIZE_OF_ALL_CLONED_REPOS, TOTAL_VULNS

    # Variable used to track repos analyzed for accurate storage metrics
    unique_repo_paths: set[str] = set()

    # Point 1, 3, 4 , 6
    for owner_repo, patch_commit, vuln_commits in zip(patch_vuln_df["repo"], patch_vuln_df["patch_commit"], patch_vuln_df["vuln_hashes"]):
        
        # Skip if there are no vuln commits to analyze
        if vuln_commits == []:
            logging.warning(f"No vulnerability commits found for repo: {owner_repo}. Skipping...")
            continue

        try:
            repo_path = find_repo_path(owner_repo)
            if repo_path is None:
                logging.error(f"Repository path not found for {owner_repo}, skipping this entry.")
                continue
            logging.info(f"Repository path for {owner_repo}: {repo_path}")
        except Exception as e:
            logging.error(f"Error finding repository path for {owner_repo}: {e}")
            continue  # Skip this repo and move to the next

        commits_to_analyze: list[str] = [patch_commit]
        commits_to_analyze.extend(vuln_commits)

        try:
            # Vars for point 3 and point 4
            temp_repo: Repository = Repository(str(repo_path), only_commits=commits_to_analyze, order='reverse')
            logging.info(f"Initialized temp repository for {owner_repo}: {temp_repo}")
        except Exception as e:
            logging.error(f"Failed to initialize repository for {owner_repo}: {e}")
            continue

        patch_author: Optional[str] = None
        patch_author_date: Optional[datetime] = None
        patch_hash: str = ""
        is_patch: bool = True
        temp_repo_path: str = ""

        # Loop through each commit in the repository
        for commit in temp_repo.traverse_commits():  # First commit will be analyzed
            logging.info(f"Analyzing commit in {temp_repo} with hash {commit.hash}")

            try:
                # Code for point 1: Tracking repo size
                if commit.project_path not in unique_repo_paths:
                    temp_repo_path = commit.project_path  
                    unique_repo_paths.add(temp_repo_path)
                    repo_size: float = get_directory_size(temp_repo_path) / (1024 * 1024)  # Convert to MB
                    SIZE_OF_ALL_CLONED_REPOS += repo_size
                    logging.info(f"Repo size for {temp_repo_path} added. Total size: {SIZE_OF_ALL_CLONED_REPOS} MB")
            except Exception as e:
                logging.error(f"Error calculating repo size for {commit.project_path}: {e}")
                continue  # Continue to next commit if size calculation fails

            try:
                # Handling patch commit (first commit in the list)
                if is_patch:
                    patch_author_date = commit.author_date
                    patch_author = commit.author.email  # Email is typically a string
                    patch_hash = commit.hash

                    TOTAL_PATCH_COMMITS_W_VULN_COMMIT += 1
                    logging.info(f"Patch commit found: {patch_hash}. Total patches with vuln commits: {TOTAL_PATCH_COMMITS_W_VULN_COMMIT}")
                    is_patch = False
                    continue  # Skip the patch commit in the next steps

                # Handling vulnerability commit (following commits after patch)
                vuln_author: Optional[str] = None
                vuln_author_date: Optional[datetime] = commit.author_date
                vuln_hash = commit.hash
                vuln_author = commit.author.email

                # Point 3: Calculate difference between patch and vuln dates in months
                if patch_author_date and vuln_author_date:
                    difference = relativedelta(patch_author_date, vuln_author_date)
                    months_difference = (difference.years or 0) * 12 + (difference.months or 0)
                    TOTAL_NUM_MONTHS_BETWEEN += months_difference
                    logging.info(f"Month difference between patch and vuln: {months_difference} months.")
                else:
                    logging.warning("Missing date values for patch or vuln commit. Skipping date difference calculation.")
                
                # Point 4: Count commits between patch and vuln commit
                try:
                    commit_count: int = get_commits_between(temp_repo_path, vuln_hash, patch_hash)
                    TOTAL_NUM_COMMITS_BETWEEN += commit_count
                    logging.info(f"Commits between vuln and patch: {commit_count}. Total commits between: {TOTAL_NUM_COMMITS_BETWEEN}")
                except Exception as e:
                    logging.error(f"Error counting commits between {vuln_hash} and {patch_hash}: {e}")
                    continue  # Skip if commit counting fails

                # Point 6: Compare patch and vuln author
                if patch_author == vuln_author:
                    BY_SAME_PERSON += 1
                    logging.info(f"Patch and vuln by same author: {patch_author}. Total: {BY_SAME_PERSON}")

                # Point 2: Get total number of vulnerabilities
                TOTAL_VULNS += len(vuln_commits)
                logging.info(f"Total vulnerabilities so far: {TOTAL_VULNS}")

            except Exception as e:
                logging.error(f"Error processing commit {commit.hash} in repo {owner_repo}: {e}")
                continue  # Skip this commit and continue to next one
    

def get_commits_between(repo_path: str, vuln_hash: str, patch_hash: str) -> int:
    """
    Calculate the number of commits between two given commit hashes.

    :param repo_path: Path to the repository.
    :param vuln_hash: The commit hash of the vulnerability.
    :param patch_hash: The commit hash of the patch.
    :return: The number of commits between the two commit hashes, or -1 if an error occurs.
    """
    # Initialize variables to store commit positions
    commit_position_vuln = None
    commit_position_patch = None
    commit_count = 0

    # Validate repo_path
    if not Path(repo_path).exists():
        error_message = f"Repository path {repo_path} does not exist."
        logging.error(error_message)
        return None  # Invalid repo path


    repo = Repository(path_to_repo=)
    from_commit=vuln_hash,to_commit=patch_hash,order='reverse'
    # Try to open the repository
    try:
        repo = Repository(repo_path)
    except Exception as e:
        error_message = f"Failed to open the repository at {repo_path}. Error: {str(e)}"
        logging.error(error_message)
        return None  # Return -1 to indicate an error opening the repository

    # Iterate over the commits in the repository
    for commit in repo.traverse_commits():
        try:
            if commit.hash == vuln_hash:
                commit_position_vuln = commit_count
            if commit.hash == patch_hash:
                commit_position_patch = commit_count
        except AttributeError as e:
            logging.error(f"Error processing commit {commit}: {str(e)}")
            continue  # Skip this commit and proceed with the next one

        # Increment the commit counter
        commit_count += 1
        
        # If both commits are found, exit the loop early (optional for performance)
        if commit_position_vuln is not None and commit_position_patch is not None:
            break

    # If both commit positions are found, return the number of commits between them
    if commit_position_vuln is not None and commit_position_patch is not None:
        return abs(commit_position_patch - commit_position_vuln)
    else:
        # Log the error if either commit is not found and return 0 instead of raising an error
        error_message = f"One or both commit hashes ({vuln_hash}, {patch_hash}) were not found in the repository at {repo_path}."
        logging.error(error_message)
        return 0  # Return a default value to indicate an error occurred

def calc_final_values(patch_vuln_df: pd.DataFrame) -> None:
    """
    Calculating final values and logging the results to a file.

    :param patch_vuln_df: The dataframe containing patch and vulnerability information.
    """
    try:
        logging.info("Starting the calculation of final values.")

        # Define the values
        total_entries = len(patch_vuln_df)
        if TOTAL_PATCH_COMMITS_W_VULN_COMMIT == 0:
            logging.warning("TOTAL_PATCH_COMMITS_W_VULN_COMMIT is 0. Average calculations may be invalid.")
            average_num_months_between_vuln_n_patch = 0
            average_num_commits_between_vuln_n_patch = 0
            average_num_of_vulns_to_patch = 0
        else:
            patches_without_vuln = total_entries - TOTAL_PATCH_COMMITS_W_VULN_COMMIT
            average_num_months_between_vuln_n_patch = TOTAL_NUM_MONTHS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT
            average_num_commits_between_vuln_n_patch = TOTAL_NUM_COMMITS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT
            average_num_of_vulns_to_patch = TOTAL_VULNS / TOTAL_PATCH_COMMITS_W_VULN_COMMIT

        if BY_SAME_PERSON == 0:
            logging.warning("BY_SAME_PERSON is 0. Percentage calculation may be invalid.")
            percentage_of_vuln_n_patch_by_same_person = 0
        else:
            percentage_of_vuln_n_patch_by_same_person = (TOTAL_VULNS / BY_SAME_PERSON) #* 100

        output_file = "vuln_patch_metrics_11.txt"
        
        try:
            # Write metrics to file
            with open(output_file, "w") as f:
                ### Get all global variable values for validation / debugging
                f.write(f"Size of all cloned repos: {SIZE_OF_ALL_CLONED_REPOS}\n")
                f.write(f"Total Vulns: {TOTAL_VULNS}\n")
                f.write(f"Total patch commits with vuln commit (matches): {TOTAL_PATCH_COMMITS_W_VULN_COMMIT}\n")
                f.write(f"Number of vulns fixed by the same person: {BY_SAME_PERSON}\n")
                ### below global is never used
                # f.write(f"Percentage of vulns fixed by the same person: {PERCENTAGE_OF_VULN_N_PATCH_BY_SAME_PERSON}%\n")
                f.write(f"Total number of months between commits: {TOTAL_NUM_MONTHS_BETWEEN}\n")
                f.write(f"Total number of commits between: {TOTAL_NUM_COMMITS_BETWEEN}\n")
                f.write(f"\n")
                f.write(f"\n")
                f.write(f"\n")
                f.write(f"\n")
                f.write(f"\n")
                f.write(f"\n")


                f.write(f"### Point 2\n")
                f.write(f"Total Entries: {total_entries}\n")
                f.write(f"Patches Without Vulnerability: {patches_without_vuln}\n\n")

                f.write(f"### Point 3\n")
                f.write(f"Average Number of Months Between Vulnerability and Patch: {average_num_months_between_vuln_n_patch:.2f}\n\n")

                f.write(f"### Point 4\n")
                f.write(f"Average Number of Commits Between Vulnerability and Patch: {average_num_commits_between_vuln_n_patch:.2f}\n\n")

                f.write(f"### Point 5\n")
                f.write(f"Average Number of Vulnerabilities per Patch: {average_num_of_vulns_to_patch:.2f}\n\n")

                f.write(f"### Point 6\n")
                f.write(f"Percentage of Vulnerabilities and Patches by the Same Person: {percentage_of_vuln_n_patch_by_same_person:.2f}%\n")

            logging.info(f"Metrics written to {output_file}")
        
        except IOError as e:
            logging.error(f"Error writing to file {output_file}. IOError: {str(e)}")
            raise  # Re-raise the exception to handle it further up the stack if needed
        
    except Exception as e:
        logging.error(f"An error occurred while calculating final values: {str(e)}")


def main():
    

    
    df = convert_jsonl_to_df(MATCH_FILES)

    if df.empty:
        logging.error("Dataframe is empty")
        sys.exit(1)
    else:
        logging.info("converted the df successfully")
        logging.info("First 5 rows of the DataFrame:\n%s", df.head().to_string())

    # Apply functions to create new columns
    df["vuln_files"] = df["vuln_commits"].apply(extract_file_paths)
    df["vuln_hashes"] = df["vuln_commits"].apply(extract_commit_hashes)

    # Drop the original vuln_commits column if not needed
    df.drop(columns=["vuln_commits"], inplace=True)
    logging.info("First 100 rows of UPDATED DataFrame:\n%s", df.head().to_string())

    # try:
    #     df[['vuln_files', 'vuln_commits']] = df['vuln_commits'].apply(safe_extract_vuln_files_commits).apply(pd.Ser)
    #     logging.info("Successfully processed 'vuln_commits' column.")
    # except Exception as e:
    #     logging.critical(f"Critical failure while applying function to DataFrame: {e}", exc_info=True)

    # logging.info("added the columns for the vulns...")


    ### Code to run on debug partition
    # Assuming patch_vuln_df is your existing DataFrame
    first_100_rows_df = df.head(100)
    iterate_and_calculate(first_100_rows_df)
    calc_final_values(first_100_rows_df)

    # iterate_and_calculate(df)
    # calc_final_values(df)
    logging.info("Done! Done! Done!")


if __name__ == "__main__":
    main()
