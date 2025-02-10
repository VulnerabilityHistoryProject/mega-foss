
import sys
import logging
import error_handling as handle








### TO-DO ###
# make sure that when I call functions in error_handling, to use Pass or continue keyword to skip to the next thing
## ***** above is very important    
# copy all code over and adjust variable names and add necessary error handling for skipping messed up cases
# write code to get the previous commit (the one directly before the patch) this way we can compare that to the other hash.
# write code to get the specific path to the git repo of the selected FOSS Project for the specific patch commit from list in json. Fill PATH_SELECTED_REPO:str = "" variable 
# write code to get the vuln changes for CHANGES VULN COMMIT in the same format as the patch commit. Reusability!
# write code to get the parent directory with all the .git repos. Use error handling to make sure there is a .git file
# write code to get the name / directory of the FOSS project in the json and verify it exists in the parent directory with all .git repos.
# write code to write the original patch commit, directly prev commit, and the suspected vuln commit (or replace with error if unable to find), and changes to a new json file --> This is the solution
# write correct shebang at the top of script aka find location of python3 on RC
# put all paths into the .env file when I login to RC and find everything on my terminal. Can I carry the .env file with me??? How are env vars handled on RC?
# write code to write the commit changes to the json file (this is already kinda done, but I need to clean it up)
# add env variables to .env 
# go back through all setters in cve_config and write functions to actually get the data in the fields. Like for Vuln classifier. How do I get that info ?
# answer this question --> Where am I getting path selected repo, the repo that's selected for that particular iteration of for loop
## Create another file / section that focuses on analyzing the dataset once json data is processed that we have with python. Doesn't necessarily have to be 
## run in the script. It can be run after we get the data. Maybe make a jupyter notebook?


class SCRIPT_CONFIG:
    """
    There will only be 1 instance of the SCRIPT_CONFIG class at any one time.
    Class methods should primarily be used here.
    """
    # Initialize the class-level logger and immutability flag
    basic_logger = logging.getLogger("basic_logger")
    robust_logger = None
    _variables_set = False

    # Class-level environment variable placeholders
    GIT_ALL_REPOS_DIR = None
    PATCH_COMMITS_JSON = None
    OUTPUT_DIR_JSON = None
    LOGGING_DIR = None

    def __init__(self):
        # Call the method to load environment variables
        self._initialize_environment_variables()
        self._ensure_immutable()
        self._initialize_robust_logging()

    @classmethod
    def _initialize_environment_variables(cls):
        """
        Calls the external method to load and validate environment variables.
        """
        variables_to_check = [
            "GIT_ALL_REPOS_DIR", 
            "PATCH_COMMITS_JSON", 
            "OUTPUT_DIR_JSON", 
            "LOGGING_DIR"
        ]
        
        # Call the function from the other file to load the environment variables
        handle.safe_get_env_vars(cls, variables_to_check)

        # Set the flag indicating that the variables have been loaded
        cls._variables_set = True

    @classmethod
    def _ensure_immutable(cls, variable_name: str) -> None:
        """
        Helper method to enforce immutability once a variable has been set.
        Logs the error and exits the program if the variable has already been set.
        """
        if getattr(cls, variable_name, None) is not None:
            cls.basic_logger.error(f"Attempt to modify {variable_name} after it has been set.")
            sys.exit(1)
    
    @classmethod
    def _initialize_robust_logging(cls)->None:
        ### Setup Robust Logging ###
        cls.robust_logger = logging.getLogger("robust_logger")
    

if __name__ == "__main__":
    config = SCRIPT_CONFIG()

    
    