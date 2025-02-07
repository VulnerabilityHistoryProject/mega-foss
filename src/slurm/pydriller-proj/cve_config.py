import logging

import error_handling as handle



import logging
import os

import logging
import os

import logging
import sys

class SCRIPT_CONFIG:
    
    def __init__(self):
        # Initialize the logger
        self.basic_logger = logging.getLogger("basic_logger")
        # Call the method to load environment variables
        self._initialize_environment_variables()

        
        # Flag to indicate if any environment variables have been set
        self._variables_set = False

    @classmethod
    def _initialize_environment_variables(cls):
        """
        Loads essential environment variables and stores them as class attributes.
        Calls the safe_get_env_vars function to validate environment variables.
        """
        variables_to_check = [
            "GIT_ALL_REPOS_DIR", 
            "PATCH_COMMITS_JSON", 
            "OUTPUT_DIR_JSON", 
            "LOGGING_DIR"
        ]
        handle.safe_get_env_vars(cls, variables_to_check)

    def _ensure_immutable(self, variable_name: str) -> None:
        """
        Helper method to enforce immutability once a variable has been set.
        Logs the error and exits the program if the variable has already been set.
        """
        if self._variables_set:
            # Log the error using the basic logger
            self.basic_logger.error(f"Attempt to modify {variable_name} after it has been set.")
            # Quit the program
            sys.exit(1)

    @property
    def git_all_repos_dir(self):
        """Getter for the GIT_ALL_REPOS_DIR environment variable."""
        return self._git_all_repos_dir

    @git_all_repos_dir.setter
    def git_all_repos_dir(self, value: str):
        """Setter for the GIT_ALL_REPOS_DIR environment variable."""
        self._ensure_immutable("GIT_ALL_REPOS_DIR")
        self._git_all_repos_dir = value
        self._variables_set = True

    @property
    def patch_commits_json(self):
        """Getter for the PATCH_COMMITS_JSON environment variable."""
        return self._patch_commits_json

    @patch_commits_json.setter
    def patch_commits_json(self, value: str):
        """Setter for the PATCH_COMMITS_JSON environment variable."""
        self._ensure_immutable("PATCH_COMMITS_JSON")
        self._patch_commits_json = value
        self._variables_set = True

    @property
    def output_dir_json(self):
        """Getter for the OUTPUT_DIR_JSON environment variable."""
        return self._output_dir_json

    @output_dir_json.setter
    def output_dir_json(self, value: str):
        """Setter for the OUTPUT_DIR_JSON environment variable."""
        self._ensure_immutable("OUTPUT_DIR_JSON")
        self._output_dir_json = value
        self._variables_set = True

    @property
    def logging_dir(self):
        """Getter for the LOGGING_DIR environment variable."""
        return self._logging_dir

    @logging_dir.setter
    def logging_dir(self, value: str):
        """Setter for the LOGGING_DIR environment variable."""
        self._ensure_immutable("LOGGING_DIR")
        self._logging_dir = value
        self._variables_set = True

class CVE:
    def __init__(self):
        """Initialize an instance of CVE with default empty values."""
        # Get the robust logger first
        self.robust_logger = logging.getLogger("robust_logger")
        self._cve_id: str = ""
        self._path_selected_repo: str = ""
        self._hash_patch_commit: str = ""
        self._hash_vuln_commit: str = ""
        self._mod_files_by_patch: set = set()
        self._mod_files_by_vuln_commit: set = set()
        self._changes_patch_commit: dict = {}
        self._changes_vuln_commit: dict = {}

    @property
    def cve_id(self) -> str:
        return self._cve_id

    @cve_id.setter
    def cve_id(self, value: str) -> None:
        self._cve_id = value

    @property
    def path_selected_repo(self) -> str:
        return self._path_selected_repo

    @path_selected_repo.setter
    def path_selected_repo(self, value: str) -> None:
        self._path_selected_repo = value

    @property
    def hash_patch_commit(self) -> str:
        return self._hash_patch_commit

    @hash_patch_commit.setter
    def hash_patch_commit(self, value: str) -> None:
        self._hash_patch_commit = value

    @property
    def hash_vuln_commit(self) -> str:
        return self._hash_vuln_commit

    @hash_vuln_commit.setter
    def hash_vuln_commit(self, value: str) -> None:
        self._hash_vuln_commit = value

    @property
    def mod_files_by_patch(self) -> set:
        return self._mod_files_by_patch

    @mod_files_by_patch.setter
    def mod_files_by_patch(self, value: set) -> None:
        self._mod_files_by_patch = value

    @property
    def mod_files_by_vuln_commit(self) -> set:
        return self._mod_files_by_vuln_commit

    @mod_files_by_vuln_commit.setter
    def mod_files_by_vuln_commit(self, value: set) -> None:
        self._mod_files_by_vuln_commit = value

    @property
    def changes_patch_commit(self) -> dict:
        return self._changes_patch_commit

    @changes_patch_commit.setter
    def changes_patch_commit(self, value: dict) -> None:
        self._changes_patch_commit = value

    @property
    def changes_vuln_commit(self) -> dict:
        return self._changes_vuln_commit

    @changes_vuln_commit.setter
    def changes_vuln_commit(self, value: dict) -> None:
        self._changes_vuln_commit = value

    
class CVE:
    CVE_ID: str = ""
    PATH_SELECTED_REPO: str = ""
    HASH_PATCH_COMMIT: str = ""
    HASH_VULN_COMMIT: str = ""
    MOD_FILES_BY_PATCH: set = set()
    MOD_FILES_BY_VULN_COMMIT: set = set()
    CHANGES_PATCH_COMMIT: dict = {}
    CHANGES_VULN_COMMIT: dict = {}

    @classmethod
    def initialize(cls):
        """Initialize missing global variables with default values."""
        for attr, default in cls.__dict__.items():
            if not attr.startswith("__") and getattr(cls, attr) in (None, ""):
                logger.error(f"Global variable '{attr}' is not initialized. Initializing it.")
                setattr(cls, attr, default)

        logger.info("CVE config initialized.")

    @classmethod
    

