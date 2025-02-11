
import sys
import logging 
from error_handling import logger_config
from error_handling import handle_errors as handle
from typing import ClassVar
from pydantic import BaseModel






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


class SCRIPT_CONFIG(BaseModel):
    """
    There will only be 1 instance of the SCRIPT_CONFIG class at any one time.
    Class methods should primarily be used here.
    """
    # Initialize the class-level logger and immutability flag
    # _basic_logger: ClassVar[logging.Logger] = logging.getLogger("basic_logger")
    _robust_logger: ClassVar[logging.Logger] = None
    _variables_set: ClassVar[bool] = False

    # Class-level environment variable placeholders
    _ROOT_DIR: ClassVar[str] = None # directory that holds all of the open source projects
    _PATCH_COMMITS_JSON_FILE: ClassVar[str] = None
    _OUTPUT_DIR_JSON: ClassVar[str] = None
    _LOGGING_DIR: ClassVar[str] = None

    def __init__(self, basic_logger:logging.Logger)-> None:
        # Call the method to load environment variables
        self._basic_logger = basic_logger
        self._initialize_environment_variables()
        self._initialize_robust_logging()

    @classmethod
    def _initialize_environment_variables(cls) -> None:
        """
        Calls the external method to load and validate environment variables.
        """
        variables_to_check: list[str] = [
            "_ROOT_DIR", 
            "_PATCH_COMMITS_JSON_FILE", 
            "_OUTPUT_DIR_JSON", 
            "_LOGGING_DIR"
        ]
        
        # Call the function from the other file to load the environment variables
        handle.safe_get_env_vars(cls, variables_to_check)

        # Set the flag indicating that the variables have been loaded
        cls._variables_set = True

    # Class-Level getter for _basic_logger
    @classmethod
    def get_basic_logger(cls) -> logging.Logger:
        return cls._basic_logger

    # Class-level getter for _robust_logger
    @classmethod
    def get_robust_logger(cls) -> logging.Logger:
        return cls._robust_logger

    @classmethod
    def _initialize_robust_logging(cls)->None:
        ### Setup Robust Logging ###
        cls._robust_logger = logger_config.setup_robust_logging()

    

    
    
    # Class-level getter for _ROOT_DIR
    @classmethod
    def get_ROOT_DIR(cls):
        """
        Get the root diretory that has all the FOSS Projects

        Returns:
            _type_: _description_
        """
        return cls._ROOT_DIR

    # Class-level setter for _ROOT_DIR
    @classmethod
    def set_ROOT_DIR(cls, value: str) -> None:
        cls._ROOT_DIR = value

    # Class-level getter for PATCH_COMMITS_JSON_FILE
    @classmethod
    def get_PATCH_COMMITS_JSON_FILE(cls) -> str:
        return cls._PATCH_COMMITS_JSON_FILE

    # Class-level setter for PATCH_COMMITS_JSON_FILE
    @classmethod
    def set_PATCH_COMMITS_JSON_FILE(cls, value: str) -> None:
        cls._PATCH_COMMITS_JSON_FILE = value
    
    # Class-level getter for OUTPUT_DIR_JSON
    @classmethod
    def get_OUTPUT_DIR_JSON(cls) -> str:
        return cls._OUTPUT_DIR_JSON

    # Class-level setter for OUTPUT_DIR_JSON
    @classmethod
    def set_OUTPUT_DIR_JSON(cls, value: str)-> None:
        cls._OUTPUT_DIR_JSON = value
    '''
    
    '''
    # Class-level getter for LOGGING_DIR
    @classmethod
    def get_LOGGING_DIR(cls) -> str:
        return cls._LOGGING_DIR

    # Class-level setter for LOGGING_DIR
    @classmethod
    def set_LOGGING_DIR(cls, value: str)-> None:
        cls._LOGGING_DIR = value



if __name__ == "__main__":
    config = SCRIPT_CONFIG()

    
    