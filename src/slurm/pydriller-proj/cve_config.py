import logging
import os
import sys

import error_handling as handle



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

class Vulnerability_Classifier:
    def __init__(self,cve_id:str = ""):
        """ Classify's vulnerability based on factors related to implementation and severity"""
        self._cve_id:str = cve_id
        self._adds_code: bool = False
        self._deletes_code:bool = False
        self._refactors_code: bool = False

        self._changes_lines: bool = False
        self._changes_functions: bool = False
        self._changes_files: bool = False
        
        self._is_prev_commit_to_patch: bool = False
        self._patch_partial_fix: bool = False

        self._number_of_patch_commits_for_vuln: int = 1 # if tihs 
        self._number_of_vulns_fixed_by_patch: int = 1
        

# patch commit class
# vuln commit class
# CVE / vulnerability class...
# I guess. When I iterate through the json, I want to just instantiate one class. I don't
# want a bunch of classes flying around.


class CVE(Vulnerability_Classifier):
    def __init__(self,path_selected_repo: str = "",hash_patch_commit:str = ""):
        """"""
        
        ### Setup Robust Logging ###
        self.robust_logger = logging.getLogger("robust_logger")

        ### Repo Info ###
        ############################################################################
        self._path_selected_repo: str = path_selected_repo

        ### Patch Commit Info ###
        ############################################################################
        self._hash_patch_commits: list[str] = []
        self._hash_patch_commits.append(hash_patch_commit)

        self._mod_files_by_patch: list[str] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        self._changes_by_patch_commit: dict = {}
       
        



        
        
        
        


        ### Vuln Commit Info ###
        ############################################################################
        self._hash_vuln_commits: list[str] = []  ### This is the object of this entire project ###
        self._mod_files_by_vuln_commit: list[str] = []
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
        self._hash_vuln_commit.append(value)

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

    



