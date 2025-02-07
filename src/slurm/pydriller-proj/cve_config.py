import logging

import error_handling as handle



import logging
import os

import logging
import os

import logging
import sys

import logging
import sys

class SCRIPT_CONFIG:
    # Initialize the class-level logger and immutability flag
    basic_logger = logging.getLogger("basic_logger")
    _variables_set = False

    # Class-level environment variable placeholders
    GIT_ALL_REPOS_DIR = None
    PATCH_COMMITS_JSON = None
    OUTPUT_DIR_JSON = None
    LOGGING_DIR = None

    def __init__(self):
        # Call the method to load environment variables
        self._initialize_environment_variables()

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

    

    

