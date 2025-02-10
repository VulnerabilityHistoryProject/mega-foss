import logging
import os
import sys
from typing import Any

import src.error_handling.handle_errors as handle

#from pydriller import Repository, Commit, ModifiedFile
import pydriller


    
class Patch_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the patch commit??
    """
    def __init__(self):

        super().__init__() # Calls the next class in MRO
        ### TO-DO ###
        # Continue reading papers to refine this list of fieds
        self._adds_code: bool = False
        self._deletes_code:bool = False
        self._refactors_code: bool = False

        self._changes_lines: bool = False
        self._changes_functions: bool = False
        self._changes_files: bool = False
        
        
        self._patch_partial_fix: bool = False

        self._number_of_vulns_fixed_by_patch: int = 1 # Sometimes multiple vulns are fixed by a single patch
        # The field above is going to be interesting to try and track... tuff problem
  
    
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
    def patch_partial_fix(self):
        return self._patch_partial_fix

    @patch_partial_fix.setter
    def patch_partial_fix(self, value: bool):
        self._patch_partial_fix = value

    
    @property
    def number_of_vulns_fixed_by_patch(self):
        return self._number_of_vulns_fixed_by_patch

    @number_of_vulns_fixed_by_patch.setter
    def number_of_vulns_fixed_by_patch(self, value: int):
        self._number_of_vulns_fixed_by_patch = value


class Patch_Commits(pydriller.Commit):
    """
    All the data to capture from the Patch commits
    """
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

class Vuln_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the 
    """
    def __init__(self):

        super().__init__() # Calls the next class in MRO
        """ Classify's vulnerability based on factors related to implementation and severity"""
        ### TO-DO ###
        # Continue reading papers to refine this list of fieds
        self._adds_code: bool = False
        self._deletes_code:bool = False
        self._refactors_code: bool = False

        self._changes_lines: bool = False
        self._changes_functions: bool = False
        self._changes_files: bool = False
        
        self._is_prev_commit_to_patch = False
        self._was_patch_partial_fix: bool = False # did the patch only partially fix this vuln? True if num of patch commits (field below is greater than 1)

        self._number_of_patch_commits_for_vuln: int = 1 # Sometimes multiple patches are needed to fix a single vuln
  
    
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

class Vuln_Commits(Patch_Commits):
    """
    Every Vulnerable Commit has a corresponding patch commit to go along with it.
    There can also be multiple vulns that correspond to a single patch commit
    Args:
        Patch_Commit (_type_): _description_
    """
    def __init__(self):
        super().__init__() # Calls the next class in MRO

        ### Vuln Commit Info ###
        ############################################################################
        self._hash_vuln_commits: list[str] = []  ### This is the object of this entire project ###
        self._mod_files_by_vuln_commits: list[str] = []
        self._changes_vuln_commits: dict = {}
    
    
    @property
    def hash_vuln_commits(self) -> str:
        return self._hash_vuln_commits

    @hash_vuln_commits.setter
    def hash_vuln_commits(self, value: str) -> None:
        self._hash_vuln_commits.append(value)

    

    @property
    def mod_files_by_vuln_commits(self) -> set:
        return self._mod_files_by_vuln_commits

    @mod_files_by_vuln_commits.setter
    def mod_files_by_vuln_commits(self, value: set) -> None:
        self._mod_files_by_vuln_commits = value

    

    @property
    def changes_vuln_commits(self) -> dict:
        return self._changes_vuln_commits

    @changes_vuln_commits.setter
    def changes_vuln_commits(self, value: dict) -> None:
        self._changes_vuln_commits = value

# patch commit class
# vuln commit class
# CVE / vulnerability class...
# I guess. When I iterate through the json, I want to just instantiate one class. I don't
# want a bunch of classes flying around.


# I want a CVE to have, a vuln classifier, a patch commit class, and a vuln commit class


class CVE(Vulnerability_Classifier,Vuln_Commits):
    """
    A CVE instance should contain everything. Vuln classifier, vuln commits, patch commits
    Args:
        Vulnerability_Classifier (_type_): _description_
        Vuln_Commits (_type_): _description_
    """
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
