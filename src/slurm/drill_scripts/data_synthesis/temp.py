



"""
Obtaining ...

1. Total size of the cloned repos
2. Total number of vulnerability inducing commits (vuln commits) found & (& num of patches missing a vuln (not found))
3. Average number of months between vuln commit and patch commit (or fix)
4. Average number of commits between the vuln commit & patch commit (or fix)
5. Average number of vuln commits fixed by patch commit (or fix)
6. Percentage of vulns where the vuln commit and fix were made by the same person
"""



import os
import shutil
from pydriller import Repository, Commit
from datetime import datetime
from dateutil.relativedelta import relativedelta
from git import Repo

# Calculate repo size
def get_directory_size(path: str) -> float:
    size: float = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            size += os.path.getsize(fp)
    return size


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

### Variable used to track repos analyzed for Point 1 so that we get accurate storage metrics
unique_repo_paths: set[str] = set()

### Point 1, 3, 4 , 6
for owner_repo, patch_commit, vuln_commits in zip(
    patch_vuln_df["repo"], 
    patch_vuln_df["patch_commit"], 
    patch_vuln_df["vuln_commits"]
):
    print("Working on iteration --{count}-- of df")

    ## If there aren't any commits to analyze, go onto the next iteration
    if vuln_commits == []:
        continue

    # Compose remote repo for pydriller
    owner, repo = owner_repo.split("/")
    remote_url: str = f"https://github.com/{owner}/{repo}.git"

    

    commits_to_analyze: list[str] = []
    commits_to_analyze.append(patch_commit)
    commits_to_analyze.extend(vuln_commits)


    ### Vars for point 3 and point 4
    temp_repo: Repository = Repository(remote_url, only_commits=commits_to_analyze, order='reverse')
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
        difference: datetime = relativedelta(patch_author_date,vuln_author_date)
        months_difference = difference.year * 12 + difference.month

        ### Point 3
        TOTAL_NUM_MONTHS_BETWEEN += months_difference
        

        ### Code for point 4
        temp_repo_obj: Repo = Repo(temp_repo_path)
        TOTAL_NUM_COMMITS_BETWEEN += temp_repo_obj.git.rev_list(f"{vuln_hash}..{patch_hash}", count=True)
        
        ### Point 6
        ### Compare patch author and vuln author
        if patch_author == vuln_author:
            BY_SAME_PERSON += 1
          
        #shutil.rmtree(temp_repo_path)

    ### Point 1
    SIZE_OF_ALL_CLONED_REPOS += repo_size

    

    ### Point 2
    TOTAL_VULNS += len(vuln_commits) ### Getting total vulns

    
    
    
    
### Point 2
TOTAL_ENTIRES = len(patch_vuln_df)
PATCHES_WO_VULN = TOTAL_ENTIRES - TOTAL_PATCH_COMMITS_W_VULN_COMMIT

### Point 3
AVERAGE_NUM_MONTHS_BETWEEN_VULN_N_PATCH: float = (TOTAL_NUM_MONTHS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT )

### Point 4
AVERAGE_NUM_COMMITS_BETWEEN_VULN_N_PATCH: float = (TOTAL_NUM_COMMITS_BETWEEN / TOTAL_PATCH_COMMITS_W_VULN_COMMIT)

### Point 5
AVERAGE_NUM_OF_VULNS_TO_PATCH: float = (TOTAL_VULNS / TOTAL_PATCH_COMMITS_W_VULN_COMMIT)


### Point 6
PERCENTAGE_OF_VULN_N_PATCH_BY_SAME_PERSON: float = (TOTAL_VULNS / BY_SAME_PERSON ) * 100


