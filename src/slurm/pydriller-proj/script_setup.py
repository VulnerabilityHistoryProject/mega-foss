

"""

Module Name: pydriller_RC_script.py

Description:
    This python script is a generalized version of VHP_ffmpeg.py. This script will read and process a list of 
    git commit hashes that correlate to documented CVE vulnerabilities from a json file. The patch commmit will
    help locate the vulnerability inducing commit hashes by utilizing pydriller's implementation of the
    popular SZZ algorithm. 

    Once found, the vulnerability inducing commit hashes will be written to a new json file corresponding to their
    respective patch inducing commit & CVE.

    This first version of the script won't be able to guarantee any degree of accuracy because it simply gathers data.

    Algorithm Process & Steps:
        1. 

        
Author: Trust-Worthy
Date: 2/4/2025

Notes:
    - pydriller must be installed on the system to run this program

Citations:
    @inbook{PyDriller,
    title = "PyDriller: Python Framework for Mining Software Repositories",
    abstract = "Software repositories contain historical and valuable information about the overall development of software systems. Mining software repositories (MSR) is nowadays considered one of the most interesting growing fields within software engineering. MSR focuses on extracting and analyzing data available in software repositories to uncover interesting, useful, and actionable information about the system. Even though MSR plays an important role in software engineering research, few tools have been created and made public to support developers in extracting information from Git repository. In this paper, we present PyDriller, a Python Framework that eases the process of mining Git. We compare our tool against the state-of-the-art Python Framework GitPython, demonstrating that PyDriller can achieve the same results with, on average, 50% less LOC and significantly lower complexity.URL: https://github.com/ishepard/pydrillerMaterials: https://doi.org/10.5281/zenodo.1327363Pre-print: https://doi.org/10.5281/zenodo.1327411",
    author = "Spadini, Davide and Aniche, Maurício and Bacchelli, Alberto",
    year = "2018",
    doi = "10.1145/3236024.3264598",
    booktitle = "The 26th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE)",
}

"""

import os 
import sys
import subprocess
import logging
import pprint
import json

import error_handling as handle

from collections import Counter
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime

from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Type

from pydriller import Git, ModifiedFile, Commit




"""global variables:

    PATH_ALL_PROJ_REPOS (str): Path to the directory containing all the FOSS project git repos.
    PATH_SELECTED_REPO (str): Path to the specific repo. This changes as the script iterates through the different patch commits in the json file.
    PATH_PATCH_COMMITS (str): Path to the json file containing all of the patch commits that fix vulnerabilities.
    PATH_OUTPUT_DIR (str): Path to the output directory where the json file with vulnerable commits will be written to.
    PATH_LOG_OUTPUT_DIR (str): Path to the output directory where the logs and errors will be stored.

    HASH_PATCH_COMMIT (str): Commit hash of the patch commit to a vulnerability.
    HASH_VULN_COMMIT (str): Commit hash of the original commit that introduced the vulnerability.
    
    MOD_FILES_BY_PATCH set[str]: Set of paths to files modified by the patch commit.
    
    CHANGES_PATCH_COMMIT dict[str,dict[str,list[tuple[int,str]]]] (dict): The key of the outer dictionary is the name of the modified file by the patch commit. The value is another dictionary. The second
                                                  dictionary has two keys, either "added" or "deleted". The added section has the code that was added by the
                                                 commit and vice-versa. The changes are in a list of tuples where the first index of the tuple is the line number, and the second tuple is the code change.

    CHANGES_VULN_COMMIT dict[str,dict[str,list[tuple[int,str]]]] (dict): Tke key of the dictionary is the modified file by the suspected vulnerable commit. The value is another dictionary. The second
                                                 dictionary has two keys, either "added" or "deleted". The added section has the code that was added by the
                                                 commit and vice-versa. The changes are a code snippet for verification and validation purposes against the CHANGES_PATCH_COMMIT. The changes are in a list 
                                                 of tuples where the first index of the tuple is the line number, and the second tuple is the code change.
    
"""


### TO-DO ###
# make sure that when I call functions in error_handling, to use Pass or continue keyword to skip to the next thing
## ***** above is very important    
# copy all code over and adjust variable names and add necessary error handling for skipping messed up cases
# write code to get the previous commit (the one directly before the patch) this way we can compare that to the other hash.
# write code to get the specific path to the git repo of the selected FOSS Project for the specific patch commit from list in json. Fill PATH_SELECTED_REPO:str = "" variable 
# write code to get the vuln changes for CHANGES VULN COMMIT in the same format as the patch commit.
# write code to get the parent directory with all the .git repos. Use error handling to make sure there is a .git file
# write code to get the name / directory of the FOSS project in the json and verify it exists in the parent directory with all .git repos.
# write code to write the original patch commit, directly prev commit, and the suspected vuln commit (or replace with error if unable to find), and changes to a new json file --> This is the solution
# write correct shebang at the top of script aka find location of python3 on RC
# put all paths into the .env file when I login to RC and find everything on my terminal. Can I carry the .env file with me??? How are env vars handled on RC?
# write code to write the commit changes to the json file (this is already kinda done, but I need to clean it up)
# add env variables to .env 

# answer this question --> Where am I getting path selected repo, 







def get_selected_repo_path() -> str:

    return None
def get_hash_patch_commit() -> None:
    return None



if __name__ == "__main__":

   # Basic logging setup for initialization phase
    log_file_path: str = 'setup_logs.txt'

    # Ensure the log file is in the same directory as the script
    log_dir: str = os.path.dirname(os.path.abspath(__file__))
    log_file: str = os.path.join(log_dir, log_file_path)

    # Set up file logging with rotation (in case the file grows large)
    logging.basicConfig(
        level=logging.DEBUG,  # Set the logging level to DEBUG
        format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
        handlers=[logging.FileHandler(log_file)]  # Only log to the file, no console output
    )

    # Get the logger
    logger: logging.Logger = logging.getLogger()

    # Example logging message
    logger.info("Basic logging setup complete.")


    

    # Call the function to initialize the globals
    initialize_globals()

    # Setup the more robust logging setup
    setup_robust_logging()

    # Initialize global variables 
    """
    These parts below will be in some sort of loop in main iterating through all of the repos in the json
    """
    get_selected_repo_path()
    get_hash_patch_commit()

    
    