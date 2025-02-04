

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

    PATH_FOSS_PROJ_REPOS (str): Path to the directory containing all the FOSS project git repos.
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
PATH_FOSS_PROJ_REPOS:str = os.getenv("GIT_REPOS_DIR")
PATH_PATCH_COMMITS:str = os.getenv("PATCH_COMMITS_JSON")
PATH_OUTPUT_DIR:str = os.getenv("OUTPUT_DIR")
 

HASH_PATCH_COMMIT:str = ""
HASH_VULN_COMMIT:str = ""

MOD_FILES_BY_PATCH:set[str] = set()


CHANGES_PATCH_COMMIT:dict[str,dict[str,str]] = {}
CHANGES_VULN_COMMIT:dict[str, dict[str,str]] = {}


### TO-DO ###
# write code to get the previous commit (the one directly before the patch) this way we can compare that to the other hash
# write code to get the vuln changes for CHANGES VULN COMMIT in the same format as the patch commit.
# 