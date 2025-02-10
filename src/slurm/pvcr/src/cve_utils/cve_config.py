import logging
import os
import sys
from typing import Any,Generator

import src.error_handling.handle_errors as handle
import src.szz_utils.szz as szz
import src.configuration.script_setup as setup

from pydriller import Repository, Commit, ModifiedFile

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
  
class Patch_Commit(Commit):
    """
    All the data to capture from the Patch commits
    """

    ### I want each patch commit to have a classifier for that patch (this means a new instance of patch commit classifier)
    def __init__(self, full_repo_path: str, hash_patch_commit_obj:Commit):

        super().__init__() # Calls the next class in MRO


        self._mod_files_by_patch_commit: list[str] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        self._changes_by_patch_commit: dict = {}



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
  
    
   

class Vuln_Commit(Vuln_Commit_Classifier):
    """
    Every Vulnerable Commit has a corresponding patch commit to go along with it.
    There can also be multiple vulns that correspond to a single patch commit
    Args:
        Patch_Commit (_type_): _description_
    """

    ### I want each vulnerable commit to have a classifier for that commit!! ###
    def __init__(self):
        super().__init__() # Calls the next class in MRO

        self._mod_files_by_vuln_commit: list[str] = []
        self._changes_vuln_commit: dict = {}
    
    
    

# patch commit class
# vuln commit class
# CVE / vulnerability class...
# I guess. When I iterate through the json, I want to just instantiate one class. I don't
# want a bunch of classes flying around.


# I want a CVE to have, a vuln classifier, a patch commit class, and a vuln commit class


class CVE():
    """
    A CVE instance should contain everything. Vuln classifier, vuln commits, patch commits
    Args:
        Vulnerability_Classifier (_type_): _description_
        Vuln_Commits (_type_): _description_
    """
    def __init__(self,cve_id: str, partial_repo_path: str,hash_patch_commit:str):
        
        # I need to get the full repo path from the partial repo path 
        # the full repo path is the path on the super computer
        # create a partial repo path field
        # and full repo path field!

        super().__init__() # Calls the next class in MRO

        ### CVE Info ###
        ############################################################################
        self._cve_id:str = cve_id

        ### Repo Info ###
        ############################################################################
        
        self._partial_repo_path: str = partial_repo_path
        self._full_repo_path: str = setup.get_full_repo_path(self._partial_repo_path)

        
        self._commits_up_to_patch: Generator = Repository( # Get all commits up to the patch commit (define order)
                                                            self._full_repo_path,
                                                            single = hash_patch_commit,
                                                            to_commit = hash_patch_commit).traverse_commits()

        ### Patch Commit Info ###
        ############################################################################
        self._hash_patch_commits: list[Patch_Commit] = []

        hash_patch_commit_obj: Commit = next(Repository( # Only get the hash patch commit object
                                                                self._full_repo_path,
                                                                single = hash_patch_commit).traverse_commits())

        self._primary_patch_commit: Patch_Commit = Patch_Commit(self._full_repo_path,hash_patch_commit_obj)
        self._hash_patch_commits.append(self._primary_patch_commit)

        ### Vuln Commit Info ###
        ### Objective of project ###
        ############################################################################
        self._hash_vuln_commits: list[Vuln_Commit] = []
    
        
    @property
    def _cve_id(self) -> str:
        return self._cve_id
    
    @_cve_id.setter
    def _cve_id(self,value:str) -> None:
        self._cve_id = value

    @property
    def _partial_repo_path(self) -> str:
        return self._partial_repo_path

    @_partial_repo_path.setter
    def _partial_repo_path(self, value: str) -> None:
        self._partial_repo_path = value

    @property
    def _full_repo_path(self) -> str:
        return self._full_repo_path

    @_full_repo_path.setter
    def _full_repo_path(self, value: str) -> None:
        self._full_repo_path = value

    @property
    def _commits_up_to_hash(self) -> Generator:
        return self._commits_up_to_hash
    
    @property
    def _primary_patch_commit(self) -> Commit:
        return self._primary_patch_commit

    @_primary_patch_commit.setter
    def _primary_patch_commit(self, value: Commit) -> None:
        self._primary_patch_commit = value
    
    @property
    def _hash_patch_commits(self) -> list[Commit]:
        return self._hash_patch_commits

    @_hash_patch_commits.setter
    def _hash_patch_commits(self, value: Patch_Commit) -> None:
        self._hash_patch_commits.append(value)