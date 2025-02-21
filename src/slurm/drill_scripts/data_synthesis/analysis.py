
import glob
import logging
import pandas as pd
import jsonlines    

import os
import shutil
from pydriller import Repository, Commit
from datetime import datetime
from dateutil.relativedelta import relativedelta
from git import Repo



# Configure logging
logging.basicConfig(
filename="analysis.txt",
level=logging.INFO,
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


def convert_jsonl_to_df(json_path:str) -> pd.DataFrame:

    data: list[object] = []

    with jsonlines.open(json_path) as reader:

        data = [entry for entry in reader]

    # Convert the list of dictionaries into a pandas DataFrame
    patch_vuln_df = pd.DataFrame(data)

    logging.info("Converted json to df")
    return patch_vuln_df

# Define a function to extract the file paths and commits
def extract_vuln_files_commits(vuln_commits):
    if vuln_commits:
        files = list(vuln_commits.keys())
        commits = [commit for commits in vuln_commits.values() for commit in commits]
        return pd.Series([files, commits])
    else:
        return pd.Series([[], []])  # Empty lists if no vuln_commits




# Calculate repo size
def get_directory_size(path: str) -> float:
    size: float = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            size += os.path.getsize(fp)
    logging.info(f"got the size for {path} repo")
    return size





def iterate_and_calculate(patch_vuln_df: pd.DataFrame):
    global NVD_ALL_REPOS, TOTAL_PATCH_COMMITS_W_VULN_COMMIT, TOTAL_NUM_MONTHS_BETWEEN,TOTAL_NUM_COMMITS_BETWEEN,BY_SAME_PERSON,SIZE_OF_ALL_CLONED_REPOS,TOTAL_VULNS

    ### Variable used to track repos analyzed for Point 1 so that we get accurate storage metrics
    unique_repo_paths: set[str] = set()
 
    ### Point 1, 3, 4 , 6
    for owner_repo, patch_commit, vuln_commits in zip(
        patch_vuln_df["repo"], 
        patch_vuln_df["patch_commit"], 
        patch_vuln_df["vuln_commits"]
    ):
        
        

        ## If there aren't any commits to analyze, go onto the next iteration
        if vuln_commits == []:
            continue

        # Compose remote repo for pydriller
        #owner, repo = owner_repo.split("/")
        #remote_url: str = f"https://github.com/{owner}/{repo}.git"

        # Search for the repository in the directory
        # repo_path_variants = [
        #     owner_repo,
        #     owner_repo.replace("/", "_"),
        #     owner_repo.replace("/", "-"),
        # ]

        # matching_repos = []
        # for variant in repo_path_variants:
        #matching_repos += glob.glob(os.path.join(NVD_ALL_REPOS, f"*{owner_repo}*"))

        repo_path = glob.glob(os.path.join(NVD_ALL_REPOS, f"*{owner_repo}*"))
        logging.info(f"got this path: {str(repo_path)}")
        # if not matching_repos:
        #     logging.warning(f"Repo not found for {owner_repo}. Skipping...")
        #     continue

        #repo_path = matching_repos[0]  # Assume the first match is correct


        commits_to_analyze: list[str] = []
        commits_to_analyze.append(patch_commit)
        commits_to_analyze.extend(vuln_commits)

        # print("commits to analyze: " + str(commits_to_analyze))

        ### Vars for point 3 and point 4
        temp_repo: Repository = Repository(repo_path, only_commits=commits_to_analyze, order='reverse')
        logging.info(f"got the temp repo: {temp_repo}")
        patch_author: str = ""
        patch_author_date: datetime = None
        patch_hash: str = ""
        is_patch: bool = True
        temp_repo_path: str = ""
        for commit in temp_repo.traverse_commits(): ### First commit will be 
            
            logging.info(f"Analyzing commits in {temp_repo}" )
            ### Code for point 1
            if commit.project_path not in unique_repo_paths:
                
                ### temp repo path updates every time there is a new path commit
                temp_repo_path = commit.project_path  
                unique_repo_paths.add(temp_repo_path)
                repo_size: float = get_directory_size(temp_repo_path) / (1024 * 1024)  # Convert to MB
                # print("temp repo path:")
                # print("uniqu repo paths" + str(unique_repo_paths))
                # print("repo size:" + str(repo_size))
                ### Point 1
                SIZE_OF_ALL_CLONED_REPOS += repo_size
                logging.info(f"Size is now: {str(SIZE_OF_ALL_CLONED_REPOS)}")
            

            if is_patch:
                patch_author_date = commit.author_date

                ### Point 6
                patch_author = commit.author.email ## is that the correct syntax? what type of object is being returned

                ### Point 4
                patch_hash = commit.hash
                ## this patch HAS at least one vuln commit
                TOTAL_PATCH_COMMITS_W_VULN_COMMIT += 1 
                logging.info(f"total patches with at least 1 vuln: {TOTAL_PATCH_COMMITS_W_VULN_COMMIT}")
                is_patch = False
                continue ### This line is INCREDIBLY Important

            ### Code for point 3 & Point 6
            ############################################################
            vuln_author: str = ""
            vuln_author_date: datetime = None

            ### Point 3
            ### reassing the value of vuln_author_date on each iteration when is_patch is false
            vuln_author_date = commit.author_date

            ### Point 4
            vuln_hash = commit.hash

            ### Point 6
            vuln_author = commit.author.email
                
            ### Point 3
            ### Calculate difference between patch date and vuln date in months

            if patch_author_date is not None and vuln_author_date is not None:
                difference = relativedelta(patch_author_date, vuln_author_date)
                #print(f"difference: {difference}")

                months_difference = (difference.years or 0) * 12 + (difference.months or 0)
                TOTAL_NUM_MONTHS_BETWEEN += months_difference
            else:
                logging.warning("Skipping calculation: Missing date values")
                


            # ### Code for point 4
            # temp_repo_obj: Repo = Repo(temp_repo_path)

            # # Make sure to count commits between vuln_hash and patch_hash, including both
            # commit_range = f"{vuln_hash}...{patch_hash}"  # Use '...' for a range between commits
            # commit_count = temp_repo_obj.git.rev_list(commit_range, count=True)

            get_commits_between(temp_repo_path,vuln_hash,patch_hash)

            # Add the result to the total
            TOTAL_NUM_COMMITS_BETWEEN += int(commit_count)

                
            ### Point 6
            ### Compare patch author and vuln author
            if patch_author == vuln_author:
                BY_SAME_PERSON += 1
                logging.info(f"number of patches and vulns by the same person: {str(BY_SAME_PERSON)}" )
            
            #shutil.rmtree(temp_repo_path)

           

            

            ### Point 2
            TOTAL_VULNS += len(vuln_commits) ### Getting total vulns
            logging.info(f"Total vulns right now: {TOTAL_VULNS}")

    



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

    # Open the repository
    repo = Repository(repo_path)

    # Iterate over the commits in the repository
    for commit in repo.traverse_commits():
        if commit.hash == vuln_hash:
            commit_position_vuln = commit_count
        if commit.hash == patch_hash:
            commit_position_patch = commit_count
        
        # Increment the commit counter
        commit_count += 1
        
        # If both commits are found, exit the loop early (optional for performance)
        if commit_position_vuln is not None and commit_position_patch is not None:
            break

    # If both commit positions are found, return the number of commits between them
    if commit_position_vuln is not None and commit_position_patch is not None:
        return abs(commit_position_patch - commit_position_vuln)
    else:
        # Log the error if either commit is not found and return -1 instead of raising an error
        error_message = f"One or both commit hashes ({vuln_hash}, {patch_hash}) were not found in the repository at {repo_path}."
        logging.error(error_message)
        return 0  # Return a default value to indicate an error occurred


def calc_final_values(patch_vuln_df: pd.DataFrame) -> None:
    """
    Calculating final values:
    """
    logging.info("about to calc the final values!")
    # Define the values
    total_entries = len(patch_vuln_df)
    patches_without_vuln = total_entries - TOTAL_PATCH_COMMITS_W_VULN_COMMIT
    average_num_months_between_vuln_n_patch = TOTAL_NUM_MONTHS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT
    average_num_commits_between_vuln_n_patch = TOTAL_NUM_COMMITS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT
    average_num_of_vulns_to_patch = TOTAL_VULNS / TOTAL_PATCH_COMMITS_W_VULN_COMMIT
    percentage_of_vuln_n_patch_by_same_person = (TOTAL_VULNS / BY_SAME_PERSON) * 100

    output_file = "vuln_patch_metrics.txt"
    with open(output_file, "w") as f:
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


    
def main():
    
    """
    Obtaining ...

    1. Total size of the cloned repos
    2. Total number of vulnerability inducing commits (vuln commits) found & (& num of patches missing a vuln (not found))
    3. Average number of months between vuln commit and patch commit (or fix)
    4. Average number of commits between the vuln commit & patch commit (or fix)
    5. Average number of vuln commits fixed by patch commit (or fix)
    6. Percentage of vulns where the vuln commit and fix were made by the same person
    """

    
    df = convert_jsonl_to_df(MATCH_FILES)
    logging.info("converted the df successfully")

    # Apply the function to create new columns
    df[['vuln_files', 'vuln_commits']] = df['vuln_commits'].apply(extract_vuln_files_commits)
    logging.info("added the columns for the vulns...")


    iterate_and_calculate(df)
    calc_final_values(df)
    logging.info("Done! Done! Done!")


if __name__ == "__main__":
    main()
