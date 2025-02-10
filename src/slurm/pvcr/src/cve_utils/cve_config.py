import logging
import os
import sys
from typing import Any

import src.error_handling.handle_errors as handle


class SCRIPT_CONFIG:
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
    

class Vulnerability_Classifier:
    def __init__(self):

        super().__init__() # Calls the next class in MRO
        """ Classify's vulnerability based on factors related to implementation and severity"""
       
        self._adds_code: bool = False
        self._deletes_code:bool = False
        self._refactors_code: bool = False

        self._changes_lines: bool = False
        self._changes_functions: bool = False
        self._changes_files: bool = False
        
        self._prev_commit_to_patch: str = ""
        self._patch_partial_fix: bool = False

        self._number_of_patch_commits_for_vuln: int = 1 # Sometimes multiple patches are needed to fix a single vuln


        self._number_of_vulns_fixed_by_patch: int = 1 # Sometimes multiple vulns are fixed by a single patch
        # The field above is going to be interesting to try and track... tuff problem

        

    
    def _get_prev_commit_to_patch(self) -> str:
        """
        Use the szz utils file to write a function that does this.
        This function should be called irrespective of the outcome of the actual bug inducing commit algo!
        """
        pass

    def _get_number_of_patch_commits_for_vuln(self) -> int:
        """
        Once the cve has been completely initialized in the child classes I can call this.

        Returns:
            int: _description_
        """
    
    @property
    def adds_code(self):
        return self._adds_code

    @adds_code.setter
    def adds_code(self, value: bool):
        self._adds_code = value

    @property
    def deletes_code(self):
        return self._deletes_code

    @deletes_code.setter
    def deletes_code(self, value: bool):
        self._deletes_code = value

    @property
    def refactors_code(self):
        return self._refactors_code

    @refactors_code.setter
    def refactors_code(self, value: bool):
        self._refactors_code = value

    @property
    def changes_lines(self):
        return self._changes_lines

    @changes_lines.setter
    def changes_lines(self, value: bool):
        self._changes_lines = value

    @property
    def changes_functions(self):
        return self._changes_functions

    @changes_functions.setter
    def changes_functions(self, value: bool):
        self._changes_functions = value

    @property
    def changes_files(self):
        return self._changes_files

    @changes_files.setter
    def changes_files(self, value: bool):
        self._changes_files = value

    @property
    def prev_commit_to_patch(self):
        return self._prev_commit_to_patch

    @prev_commit_to_patch.setter
    def prev_commit_to_patch(self, value: str):
        """
        Use the szz utils file to write a function that does this.
        This function should be called irrespective of the outcome of the actual bug inducing commit algo!
        """
        self._prev_commit_to_patch = value

    @property
    def patch_partial_fix(self):
        return self._patch_partial_fix

    @patch_partial_fix.setter
    def patch_partial_fix(self, value: bool):
        self._patch_partial_fix = value

    @property
    def number_of_patch_commits_for_vuln(self):
        return self._number_of_patch_commits_for_vuln

    @number_of_patch_commits_for_vuln.setter
    def number_of_patch_commits_for_vuln(self, value: int):
        """
        Once the cve has been completely initialized in the child classes I can call this.

        Returns:
            int: _description_
        """
        self._number_of_patch_commits_for_vuln = value

    @property
    def number_of_vulns_fixed_by_patch(self):
        return self._number_of_vulns_fixed_by_patch

    @number_of_vulns_fixed_by_patch.setter
    def number_of_vulns_fixed_by_patch(self, value: int):
        self._number_of_vulns_fixed_by_patch = value


class Patch_Commit:
    def __init__(self, hash_patch_commit:str = ""):

        super().__init__() # Calls the next class in MRO

        ### Patch Commit Info ###
        ############################################################################
        self._hash_patch_commits: list[str] = []
        self._hash_patch_commits.append(hash_patch_commit)

        self._mod_files_by_patch: list[str] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        self._changes_by_patch_commit: dict = {}


    
    @property
    def hash_patch_commits(self) -> str:
        return self._hash_patch_commits

    @hash_patch_commits.setter
    def hash_patch_commits(self, value: str) -> None:
        self._hash_patch_commits.append(value)

    @property
    def mod_files_by_patch(self) -> set:
        return self._mod_files_by_patch

    @mod_files_by_patch.setter
    def mod_files_by_patch(self, value: str) -> None:
        self._mod_files_by_patch.append(value)

    @property
    def changes_by_patch_commit(self) -> dict:
        return self._changes_by_patch_commit

    
    def set_changes_by_patch_commit(self, key: Any, value: dict) -> None:
        """Custom method to safely update the dictionary."""
        handle.safe_dict_set(self._changes_by_patch_commit,key,value)

class Vuln_Commit(Patch_Commit):
    def __init__(self):
        super().__init__() # Calls the next class in MRO

        ### Vuln Commit Info ###
        ############################################################################
        self._hash_vuln_commits: list[str] = []  ### This is the object of this entire project ###
        self._mod_files_by_vuln_commit: list[str] = []
        self._changes_vuln_commit: dict = {}


# patch commit class
# vuln commit class
# CVE / vulnerability class...
# I guess. When I iterate through the json, I want to just instantiate one class. I don't
# want a bunch of classes flying around.


# I want a CVE to have, a vuln classifier, a patch commit class, and a vuln commit class

class CVE(Vulnerability_Classifier,Vuln_Commit):
    def __init__(self,path_selected_repo: str = "",hash_patch_commit:str = "",cve_id:str = ""):
        """"""
        

        super().__init__() # Calls the next class in MRO
        ### Repo Info ###
        ############################################################################
        self._path_selected_repo: str = path_selected_repo


        ### CVE Info ###
        ############################################################################
        self._cve_id:str = cve_id
       
        
    

    @property
    def path_selected_repo(self) -> str:
        return self._path_selected_repo

    @path_selected_repo.setter
    def path_selected_repo(self, value: str) -> None:
        self._path_selected_repo = value
    
    @property
    def cve_id(self) -> str:
        return self._cve_id

    @cve_id.setter
    def cve_id(self, value: str) -> None:
        self._cve_id = value


    

   

    

    @property
    def hash_vuln_commit(self) -> str:
        return self._hash_vuln_commit

    @hash_vuln_commit.setter
    def hash_vuln_commit(self, value: str) -> None:
        self._hash_vuln_commit.append(value)

    

    @property
    def mod_files_by_vuln_commit(self) -> set:
        return self._mod_files_by_vuln_commit

    @mod_files_by_vuln_commit.setter
    def mod_files_by_vuln_commit(self, value: set) -> None:
        self._mod_files_by_vuln_commit = value

    

    @property
    def changes_vuln_commit(self) -> dict:
        return self._changes_vuln_commit

    @changes_vuln_commit.setter
    def changes_vuln_commit(self, value: dict) -> None:
        self._changes_vuln_commit = value

    



