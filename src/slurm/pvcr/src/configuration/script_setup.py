
import sys
import logging 
from error_handling import logger_config
from error_handling import handle_errors as handle
from typing import ClassVar
from pydantic import BaseModel


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

    
    