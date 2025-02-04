

"""

Module Name: pydriller_RC_script.py

Description:
    This python script is a generalized version of VHP_ffmpeg.py. This script will read and process a list of 
    git commit hashes that represent patches to CVE vulnerabilities from a json file. The patch commmit will
    help locate the vulnerability inducing commit hashes by utilizing pydriller's implementation of the
    popular SZZ algorithm. 

    Once found, the vulnerability inducing commit hashes will be written to a new json file corresponding to their
    respective patch inducing commit & CVE.

    Algorithm Process & Steps:
        1. 

        
Author: Trust-Worthy
Date: 2/4/2025

Notes:
    - pydriller must be installed on the system to run this program

"""

import subprocess
from collections import Counter
from dotenv import load_dotenv
from pathlib import Path
import os 
import pprint
import json

from pydriller import Git,ModifiedFile, Commit


"""global variables:

    PATH_ALL_PROJ_REPOS (str): Path to the directory containing all the FOSS project git repos.
    PATH_SELECTED_REPO (str): Path to the specific repo. This changes as the script iterates through the different patch commits in the json file.
    PATH_PATCH_COMMITS (str): Path to the json file containing all of the patch commits that fix vulnerabilities.
    PATH_OUTPUT_DIR (str): Path to the output directory where the json file with vulnerable commits will be written to.
    

    HASH_PATCH_COMMIT (str): Commit hash of the patch commit to a vulnerability.
    HASH_VULN_COMMIT (str): Commit hash of the original commit that introduced the vulnerability.
    
    MOD_FILES_BY_PATCH set[str]: Set of files modified by the patch commit.
    
    CHANGES_PATCH_COMMIT dict[str,dict[str,str]]: The key of the outer dictionary is the name of the modified file. The value is another dictionary. The second
                                                  dictionary has two keys, either "added" or "deleted". The added section has the code that was added by the
                                                 commit and vice-versa.
    CHANGES_VULN_COMMIT dict[str, dict[str,str]]: Tke key of the dictionarhy is the modified file by the suspected vulnerable commit. The value is another dictionary. The second
                                                 dictionary has two keys, either "added" or "deleted". The added section has the code that was added by the
                                                 commit and vice-versa. The changes are a code snippet for verification and validation purposes against the CHANGES_PATCH_COMMIT
    
"""

load_dotenv()
PATH_ALL_PROJ_REPOS:str = os.getenv("GIT_ALL_REPOS_DIR")
PATH_SELECTED_REPO:str = ""

PATH_PATCH_COMMITS:str = os.getenv("PATCH_COMMITS_JSON")
PATH_OUTPUT_DIR:str = os.getenv("OUTPUT_DIR_JSON")
 

HASH_PATCH_COMMIT:str = ""
HASH_VULN_COMMIT:str = ""

MOD_FILES_BY_PATCH:set[str] = set()


CHANGES_PATCH_COMMIT:dict[str,dict[str,str]] = {}
CHANGES_VULN_COMMIT:dict[str, dict[str,str]] = {}


### TO-DO ###
# copy all code over and adjust variable names and add necessary error handling for skipping messed up cases
# write code to get the previous commit (the one directly before the patch) this way we can compare that to the other hash.
# write code to get the specific path to the git repo of the selected FOSS Project for the specific patch commit from list in json. Fill PATH_SELECTED_REPO:str = "" variable 
# write code to get the vuln changes for CHANGES VULN COMMIT in the same format as the patch commit.
# write code to get the parent directory with all the .git repos. Use error handling to make sure there is a .git file
# write code to get the name / directory of the FOSS project in the json and verify it exists in the parent directory with all .git repos.
# write code to write the original patch commit, directly prev commit, and the suspected vuln commit (or replace with error if unable to find), and changes to a new json file --> This is the solution
# write correct shebang at the top of script aka find location of python3 on RC
# put all paths into the .env file when I login to RC and find everything on my terminal. Can I carry the .env file with me??? How are env vars handled on RC?
# write code to 


def find_modified_files(commit_hash:str = HASH_PATCH_COMMIT, repo_path:str = PATH_FFMPEG_REPO) -> set[ModifiedFile]:
    """
    Given a specific commit hash and repo via a path, returns a set of ModifiedFile objects. All items in the set are modified
    by the original commit hash.

    Args:
        commit_hash (str, optional): The hash to be analyzed. Defaults to HASH_PATCH_COMMIT.
        repo_path (str, optional): Path to repo used to analyze a commit hash. Defaults to PATH_FFMPEG_REPO.

    Returns:
        set[ModifiedFile]: Set of ModifiedFile objects that were all modified by the commit.
    """
    
    # Create empty set for files that were modified by the fixed commit
    modified_file_paths_from_fix:set[ModifiedFile] = set()

    # converting path to a Git object --> ffmpeg git repo
    ffmpeg_git_repo= Git(repo_path)

    # Getting the commit object from the fixed commit hash the fixed the vulnerability
    fixed_commit:Commit = ffmpeg_git_repo.get_commit(commit_hash)

    

    # Add modified files to the set for later reference
    for modified_file in fixed_commit.modified_files:

        # Always add the old path because that is the one what won't change
        modified_file_paths_from_fix.add(modified_file)
        PATCH_MODIFIED_FILES.add(modified_file.old_path)

        PATCH_FIXED_CHANGES[modified_file.old_path] = modified_file.diff_parsed # I want to add the changes so I can look at them later
        

    return modified_file_paths_from_fix
   
