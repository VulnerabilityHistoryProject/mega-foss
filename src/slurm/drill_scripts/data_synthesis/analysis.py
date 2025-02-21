
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
    return size




NVD_ALL_REPOS = "/shared/rc/sfs/nvd-all-repos"

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
        repo_path_variants = [
            owner_repo,
            owner_repo.replace("/", "_"),
            owner_repo.replace("/", "-"),
        ]

        matching_repos = []
        for variant in repo_path_variants:
            matching_repos += glob.glob(os.path.join(NVD_ALL_REPOS, f"*{variant}*"))

        if not matching_repos:
            logging.warning(f"Repo not found for {owner_repo}. Skipping...")
            continue

        repo_path = matching_repos[0]  # Assume the first match is correct


        commits_to_analyze: list[str] = []
        commits_to_analyze.append(patch_commit)
        commits_to_analyze.extend(vuln_commits)

        print("commits to analyze: " + str(commits_to_analyze))

        ### Vars for point 3 and point 4
        temp_repo: Repository = Repository(repo_path, only_commits=commits_to_analyze, order='reverse')
        patch_author: str = ""
        patch_author_date: datetime = None
        patch_hash: str = ""
        is_patch: bool = True
        temp_repo_path: str = ""
        for commit in temp_repo.traverse_commits(): ### First commit will be 
            
        
            ### Code for point 1
            if commit.project_path not in unique_repo_paths:
                
                ### temp repo path updates every time there is a new path commit
                temp_repo_path = commit.project_path  
                unique_repo_paths.add(temp_repo_path)
                repo_size: float = get_directory_size(temp_repo_path) / (1024 * 1024)  # Convert to MB
                print("temp repo path:")
                print("uniqu repo paths" + str(unique_repo_paths))
                print("repo size:" + str(repo_size))
            

            if is_patch:
                patch_author_date = commit.author_date

                ### Point 6
                patch_author = commit.author.email ## is that the correct syntax? what type of object is being returned

                ### Point 4
                patch_hash = commit.hash
                ## this patch HAS at least one vuln commit
                TOTAL_PATCH_COMMITS_W_VULN_COMMIT += 1 
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
                print(f"difference: {difference}")

                months_difference = (difference.years or 0) * 12 + (difference.months or 0)
                TOTAL_NUM_MONTHS_BETWEEN += months_difference
            else:
                print("Skipping calculation: Missing date values")



            

            ### Code for point 4
            temp_repo_obj: Repo = Repo(temp_repo_path)
            TOTAL_NUM_COMMITS_BETWEEN += int(temp_repo_obj.git.rev_list(f"{vuln_hash}..{patch_hash}", count=True))
            
            ### Point 6
            ### Compare patch author and vuln author
            if patch_author == vuln_author:
                BY_SAME_PERSON += 1
            
            #shutil.rmtree(temp_repo_path)

        ### Point 1
        SIZE_OF_ALL_CLONED_REPOS += repo_size

        

        ### Point 2
        TOTAL_VULNS += len(vuln_commits) ### Getting total vulns

    
    
    

def calc_final_values(patch_vuln_df: pd.DataFrame) -> None:
    """
    Calculating final values:
    """
    
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

    # Apply the function to create new columns
    df[['vuln_files', 'vuln_commits']] = df['vuln_commits'].apply(extract_vuln_files_commits)

    iterate_and_calculate(df)
    calc_final_values(df)
    logging.info("Done! Done! Done!")


if __name__ == "__main__":
    main()
