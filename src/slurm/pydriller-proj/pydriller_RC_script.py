

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

import subprocess
import os 
import sys
from collections import Counter
from dotenv import load_dotenv
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler

import pprint
import json

from pydriller import Git,ModifiedFile, Commit


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

load_dotenv()
PATH_ALL_PROJ_REPOS:str = os.getenv("GIT_ALL_REPOS_DIR")
PATH_SELECTED_REPO:str = ""

PATH_PATCH_COMMITS:str = os.getenv("PATCH_COMMITS_JSON")
PATH_OUTPUT_DIR:str = os.getenv("OUTPUT_DIR_JSON")

PATH_LOG_OUTPUT_DIR: str = os.getenv("LOGGING_DIR")



HASH_PATCH_COMMIT:str = ""
HASH_VULN_COMMIT:str = ""

MOD_FILES_BY_PATCH:set[str] = set()


CHANGES_PATCH_COMMIT:dict[str, # str = name of modified file
                          dict[str, # str = either 'added' or 'deleted'
                               list[ # list contains a tuple(line number, code)
                                   tuple[int,str]]]] = {}
CHANGES_VULN_COMMIT:dict[str, # str = name of modified file
                         dict[str, # str = either 'added' or 'deleted'
                              list[ # list contains a tuple(line number, code)
                                  tuple[int,str]]]] = {}

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
# write code to write the commit changes to the json file (this is already kinda done, but I need to clean it up)
# add env variables to .env 

# answer this question --> Where am I getting path selected repo, 


# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def initialize_globals():
    """
    Ensures that all global variables are initialized. If they are not, logs an error and initializes them.
    If the environment variables required for initialization are not found, logs the error and exits.
    """
    # Try loading environment variables
    try:
        load_dotenv()
    except Exception as e:
        logger.error(f"Error loading environment variables from .env file: {e}")
        sys.exit(1)

    # Get environment variables
    PATH_ALL_PROJ_REPOS = os.getenv("GIT_ALL_REPOS_DIR")
    PATH_PATCH_COMMITS = os.getenv("PATCH_COMMITS_JSON")
    PATH_OUTPUT_DIR = os.getenv("OUTPUT_DIR_JSON")
    PATH_LOG_OUTPUT_DIR = os.getenv("LOGGING_DIR")

    # Check if required environment variables are set
    if not PATH_ALL_PROJ_REPOS or not PATH_PATCH_COMMITS or not PATH_OUTPUT_DIR or not PATH_LOG_OUTPUT_DIR:
        logger.error("One or more required environment variables are missing. Exiting.")
        sys.exit(1)

    # If any global variables are not initialized or are empty, initialize them
    global_vars = {
        "PATH_SELECTED_REPO": "",
        "HASH_PATCH_COMMIT": "", # getting this 
        "HASH_VULN_COMMIT": "",
        "MOD_FILES_BY_PATCH": set(),
        "CHANGES_PATCH_COMMIT": {},
        "CHANGES_VULN_COMMIT": {},
    }

    for var_name, value in global_vars.items():
        if value is None or value == "":
            logger.error(f"Global variable '{var_name}' is not initialized or is empty. Initializing it.")
            if var_name == "PATH_SELECTED_REPO":
                global_vars[var_name] = "/default/path/to/selected/repo"  # Default value for this global var
            elif var_name == "HASH_PATCH_COMMIT":
                global_vars[var_name] = "default_patch_commit_hash"  # Default value for this global var
            elif var_name == "HASH_VULN_COMMIT":
                global_vars[var_name] = "default_vuln_commit_hash"  # Default value for this global var
            elif var_name == "MOD_FILES_BY_PATCH":
                global_vars[var_name] = set()  # Initialize as empty set
            elif var_name == "CHANGES_PATCH_COMMIT":
                global_vars[var_name] = {}  # Initialize as empty dict
            elif var_name == "CHANGES_VULN_COMMIT":
                global_vars[var_name] = {}  # Initialize as empty dict
        else:
            logger.info(f"Global variable '{var_name}' is already initialized.")

    # Apply the global variable values
    for var_name, value in global_vars.items():
        globals()[var_name] = value

    # Apply environment variables to the global variables
    globals()["PATH_ALL_PROJ_REPOS"] = PATH_ALL_PROJ_REPOS
    globals()["PATH_PATCH_COMMITS"] = PATH_PATCH_COMMITS
    globals()["PATH_OUTPUT_DIR"] = PATH_OUTPUT_DIR
    globals()["PATH_LOG_OUTPUT_DIR"] = PATH_LOG_OUTPUT_DIR

    logger.info("All global variables are initialized successfully.")

# Call the function to initialize the globals
initialize_globals()




def setup_logging(log_directory: str = PATH_LOG_OUTPUT_DIR):
    # Ensure the log directory exists
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)  # Create the directory if it doesn't exist

    log_file = 'error_log.txt'
    log_path = os.path.join(log_directory, log_file)

    # Check if the log file already exists in the specified directory
    if os.path.exists(log_path):
        # If the file exists, add a number suffix (e.g., error_log.txt2, error_log.txt3, etc.)
        i = 2
        while os.path.exists(os.path.join(log_directory, f'error_log.txt{i}')):
            i += 1
        log_path = os.path.join(log_directory, f'error_log.txt{i}')
    
    # Set up the rotating log file handler
    handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=10)  # 5MB per log file, up to 10 backup files
    handler.setLevel(logging.DEBUG)

    # Define the log format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s - Line: %(lineno)d')
    handler.setFormatter(formatter)

    # Add the handler to the root logger
    logging.getLogger().addHandler(handler)



def find_modified_files(patch_commit_hash: str = HASH_PATCH_COMMIT, selected_repo: str = PATH_SELECTED_REPO) -> set[ModifiedFile]:
    """
    Given a specific patch commit hash and a repo corresponding to the FOSS project, via a path, returns a set of ModifiedFile objects. 
    All items in the set are modified files by the patch commit hash.

    Args:
        patch_commit_hash (str, optional): The hash to be analyzed. Defaults to HASH_PATCH_COMMIT.
        selected_repo (str, optional): Path to repo used to analyze a commit hash. Defaults to PATH_SELECTED_REPO.

    Returns:
        set[ModifiedFile]: Set of ModifiedFile objects that were all modified by the patch commit to eliminate the CVE.
    """
    
    # Create an empty set for files that were modified by the patch commit
    modified_file_objects: set[ModifiedFile] = set()

    try:
        # Converting selected repo (path) to a Git object
        selected_git_repo_obj = Git(selected_repo)
        
        # Getting the commit object (patch) from the commit hash git object (git repo obj)
        patch_commit_obj: Commit = selected_git_repo_obj.get_commit(patch_commit_hash)

    except FileNotFoundError as e:
        logging.error(f"Repository path '{selected_repo}' not found: {e}")
        return modified_file_objects
    except ValueError as e:
        logging.error(f"Invalid commit hash '{patch_commit_hash}': {e}")
        return modified_file_objects
    except Exception as e:
        logging.critical(f"Unexpected error while accessing the repo or commit: {e}")
        return modified_file_objects

    # Process modified files and log any errors encountered
    for modified_file_obj in patch_commit_obj.modified_files:
        try:
            # Always add the old path because that's the one that won't change
            modified_file_objects.add(modified_file_obj)

            ### Uncomment line below on subsequent iterations after runnning script once ###
            # track_commit_changes(modified_file_obj)

        except AttributeError as e:
            logging.warning(f"Failed to process file '{modified_file_obj}': Missing attributes: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error while processing file '{modified_file_obj}': {e}")
            continue

    return modified_file_objects



# Make sure CHANGES_PATCH_COMMIT is initialized as a dictionary (assuming it's global)
if not isinstance(CHANGES_PATCH_COMMIT, dict):
    CHANGES_PATCH_COMMIT = {}

def track_commit_changes(modified_file_obj: ModifiedFile) -> None:
    """
    Tracks the added and deleted code in a modified file. Stores the changes in the global variable
    CHANGES_PATCH_COMMIT dictionary.

    Args:
        modified_file_obj (ModifiedFile): This is a file that was modified by a patch commit, vulnerability commit, or general commit.
    """
    try:
        # Check if 'modified_file_obj' has required attributes 'old_path' and 'diff_parsed'
        if not hasattr(modified_file_obj, 'old_path') or not hasattr(modified_file_obj, 'diff_parsed'):
            raise AttributeError(f"Missing required attributes in modified_file_obj: {modified_file_obj}")

        old_path = modified_file_obj.old_path
        diff_parsed = modified_file_obj.diff_parsed

        # Ensure old_path is a valid string
        if not isinstance(old_path, str) or not old_path:
            raise ValueError(f"Invalid 'old_path' in modified_file_obj: {old_path}")

        # Ensure diff_parsed is of an acceptable type (e.g., string, dict, list)
        if not isinstance(diff_parsed, (str, dict, list)):
            raise TypeError(f"Invalid 'diff_parsed' type in modified_file_obj: {type(diff_parsed)}")

        # Ensure CHANGES_PATCH_COMMIT is a dictionary
        if not isinstance(CHANGES_PATCH_COMMIT, dict):
            logging.error("CHANGES_PATCH_COMMIT is not a dictionary!")
            return

        # Update the CHANGES_PATCH_COMMIT dictionary
        CHANGES_PATCH_COMMIT[old_path] = diff_parsed

    except AttributeError as e:
        logging.error("AttributeError while processing modified_file_obj: %s", e)
    except ValueError as e:
        logging.error("ValueError: %s", e)
    except TypeError as e:
        logging.error("TypeError: %s", e)
    except Exception as e:
        logging.error("An unexpected error occurred while tracking commit changes: %s", e)






