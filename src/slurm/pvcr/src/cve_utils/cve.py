import logging
import os
import sys
from typing import Any,Generator, Optional, ClassVar

from error_handling import handle_errors as handle
from szz_utils import szz
from configuration import script_setup as setup
from pydriller import Repository, Commit, ModifiedFile
from pydantic import BaseModel

class Patch_Commit_Classifier(BaseModel):
    """
    The goal of this class is to answer the question: What has been changed by the patch commit??
    """
    def __init__(self) -> None:
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
        
        ### Complexity ### 
        self._dmm_unit_size: float = None
        self._dmm_unit_complexity: float = None
        self._dmm_unit_interfacing: float = None
    def classify_patch_commit(self, patch_commit_hash_obj: Commit) -> None:
        # Update the fields based on the patch commit analysis (simplified here)
        self._adds_code = patch_commit_hash_obj.insertions > 0
        self._deletes_code = patch_commit_hash_obj.deletions > 0
        self._refactors_code: bool = False
        
        self._changes_lines = None
        self._changes_functions: bool = False
        self._changes_files = patch_commit_hash_obj.files > 0

        self._patch_partial_fix: bool = False
        self._number_of_vulns_fixed_by_patch: int = 1
        
        
        self._dmm_unit_size = patch_commit_hash_obj.dmm_unit_size
        self._dmm_unit_complexity = patch_commit_hash_obj.dmm_unit_complexity
        self._dmm_unit_interfacing = patch_commit_hash_obj.dmm_unit_interfacing
  
class Patch_Commit():
    """
    All the data to capture from the Patch commits
    """
    def __init__(self, full_repo_path: str, patch_commit_hash_obj:Commit) -> None:

        super().__init__() # Calls the next class in MRO

        self._full_repo_path: str = full_repo_path


        self._patch_commit_hash_obj: Commit = patch_commit_hash_obj


        self._mod_files_by_patch_commit: list[ModifiedFile] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        
        
        self._changes_by_patch_commit: dict = {}

        # Create an instance of Patch_Commit_Classifier and associate it with this Patch_Commit instance
        self.classifier = Patch_Commit_Classifier()
        # Call the classifier method to update fields based on the patch commit object
        self.classifier.classify_patch_commit(patch_commit_hash_obj)

        ### Changes Made By Patch Commit ###
        self._mod_files_by_patch_commit.extend(patch_commit_hash_obj.modified_files) 
    
    def __eq__(self, other:object):
        return isinstance(other,Patch_Commit) and self._patch_commit_hash_obj.hash == other._patch_commit_hash_obj.hash

    def __hash__(self):
        return hash(self._patch_commit_hash_obj.hash)
    
    def get_classifier_info(self) -> dict:

        """
        Returns a dictionary containing classifier-related information.
        """
        return {
            "adds_code": self.classifier._adds_code,
            "deletes_code": self.classifier._deletes_code,
            "refactors_code": self.classifier._refactors_code,
            "changes_lines": self.classifier._changes_lines,
            "changes_functions": self.classifier._changes_functions,
            "changes_files": self.classifier._changes_files,
            "patch_partial_fix": self.classifier._patch_partial_fix,
            "number_of_vulns_fixed_by_patch": self.classifier._number_of_vulns_fixed_by_patch,
            "dmm_unit_size": self.classifier._dmm_unit_size,
            "dmm_unit_complexity": self.classifier._dmm_unit_complexity,
            "dmm_unit_interfacing": self.classifier._dmm_unit_interfacing,
        }




class Vuln_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the vulnerability?
    """
    def __init__(self) -> None:

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
        
        ### Complexity ### 
        self._dmm_unit_size: float = None
        self._dmm_unit_complexity: float = None
        self._dmm_unit_interfacing: float = None



    def classify_vuln_commit(self, vuln_commit_hash_obj: Commit) -> None:
        # Update the fields based on the vuln commit analysis (simplified here)
        self._adds_code = vuln_commit_hash_obj.insertions > 0
        self._deletes_code = vuln_commit_hash_obj.deletions > 0
        self._refactors_code: bool = False
        
        self._changes_lines = None
        self._changes_functions: bool = False
        self._changes_files = vuln_commit_hash_obj.files > 0

        self._patch_partial_fix: bool = False
        self._number_of_patch_commits_for_vuln = 1 ### IF this wasn't 1, this would be a unfixed vulnerability
        
        self._dmm_unit_size = vuln_commit_hash_obj.dmm_unit_size
        self._dmm_unit_complexity = vuln_commit_hash_obj.dmm_unit_complexity
        self._dmm_unit_interfacing = vuln_commit_hash_obj.dmm_unit_interfacing


class Vuln_Commit():
    """
    Every Vulnerable Commit has a corresponding patch commit to go along with it.
    There can also be multiple vulns that correspond to a single patch commit
    Args:
        Patch_Commit (_type_): _description_
    """

    ### I want each vulnerable commit to have a classifier for that commit!! ###
    def __init__(self, full_repo_path: str, vuln_commit_obj: Commit, patch_commit_obj: Patch_Commit) -> None:
        super().__init__() # Calls the next class in MRO
        
        self._full_repo_path: str = full_repo_path


        self._vuln_commit_hash_obj: Commit = vuln_commit_obj


        
        
        self._mod_files_by_vuln_commit: list[ModifiedFile] = []
        
        
        self._changes_vuln_commit: dict = {}

        # Create an instance of Patch_Commit_Classifier and associate it with this Patch_Commit instance
        self.classifier = Patch_Commit_Classifier()
        # Call the classifier method to update fields based on the patch commit object
        self.classifier.classify_patch_commit(patch_commit_hash_obj)

        ### Changes Made By Patch Commit ###
        self._mod_files_by_patch_commit.extend(patch_commit_hash_obj.modified_files) 
    
    def __eq__(self, other:object):
        return isinstance(other,Vuln_Commit) and self._vuln_commit_hash_obj.hash == other._vuln_commit_hash_obj.hash

    def __hash__(self):
        return hash(self._vuln_commit_hash_obj.hash)
    
    def get_classifier_info(self) -> dict:

        """
        Returns a dictionary containing classifier-related information.
        """
        return {
            "adds_code": self.classifier._adds_code,
            "deletes_code": self.classifier._deletes_code,
            "refactors_code": self.classifier._refactors_code,
            "changes_lines": self.classifier._changes_lines,
            "changes_functions": self.classifier._changes_functions,
            "changes_files": self.classifier._changes_files,
            "patch_partial_fix": self.classifier._patch_partial_fix,
            "number_of_vulns_fixed_by_patch": self.classifier._number_of_vulns_fixed_by_patch,
            "dmm_unit_size": self.classifier._dmm_unit_size,
            "dmm_unit_complexity": self.classifier._dmm_unit_complexity,
            "dmm_unit_interfacing": self.classifier._dmm_unit_interfacing,
        }
class PatchVulnBiMap:
    """Bi-directional Mapping for patch commits to vuln commits and vice-versa, indexed by CVE ID.

    There will only be one instance of this class. This will be a class level variable for the CVE class. It will collect all the processed CVEs
    """
    
    def __init__(self):
        # Maps CVE ID to a list of two dictionaries:
        # [0] = patch_to_vulns (maps patch commits to vulnerabilities they fix)
        # [1] = vuln_to_patches (maps vulnerabilities to patch commits that fix them)
        self._cve_mapping: dict[str, 
                               list[
                                   dict[Patch_Commit, set[Vuln_Commit]],  # patch -> vuln mapping
                                   dict[Vuln_Commit, set[Patch_Commit]]   # vuln -> patch mapping
                               ]] = {}


    def add_mapping(self, cve_id: str, patch: Optional[Patch_Commit] = None, vuln: Optional[Vuln_Commit] = None) -> None:
        """Adds a bidirectional mapping between a patch commit and a vulnerability commit for a given CVE ID."""
        
        # Initialize the mapping if the CVE ID is not yet present
        if cve_id not in self._cve_mapping:
            self._cve_mapping[cve_id] = [
                {Patch_Commit: set[Vuln_Commit]},  # patch_to_vulns
                {Vuln_Commit: set[Patch_Commit]}   # vuln_to_patches
            ]

        if patch and vuln:
            # Add patch -> vuln relationship for the CVE
            self._cve_mapping[cve_id][0].setdefault(patch, set()).add(vuln)

            # Add vuln -> patch relationship for the CVE
            self._cve_mapping[cve_id][1].setdefault(vuln, set()).add(patch)

        elif patch:
            # Add patch -> vuln relationship for the CVE
            self._cve_mapping[cve_id][0].setdefault(patch, set())

        elif vuln:
            # Add vuln -> patch relationship for the CVE
            self._cve_mapping[cve_id][1].setdefault(vuln, set())

    def get_patch_commits_for_cve_id(self,cve_id: str)-> set[Patch_Commit]:
        if cve_id in self._cve_mapping:
            patches: set[Patch_Commit] = self._cve_mapping[cve_id][0].keys()
            patches.add(self._cve_mapping[cve_id][1].values())

            return patches
        else:
            return None
        
    def get_vuln_commits_for_cve_id(self,cve_id: str)-> set[Vuln_Commit]:
        if cve_id in self._cve_mapping:
            vulns: set[Vuln_Commit] = self._cve_mapping[cve_id][0].values()
            vulns.add(self._cve_mapping[cve_id][1].keys())

            return vulns
        else:
            return None
        

    def get_vulns_for_patch(self, cve_id: str, patch: Patch_Commit) -> set:
        """Returns the vulnerabilities fixed by a given patch commit for the specified CVE ID."""
        if cve_id in self._cve_mapping:
            vulns = self._cve_mapping[cve_id][0].get(patch, set())
            return vulns
        return set()

    def get_patches_for_vuln(self, cve_id: str, vuln: Vuln_Commit) -> set:
        """Returns the patch commits that fix a given vulnerability commit for the specified CVE ID."""
        if cve_id in self._cve_mapping:
            patches = self._cve_mapping[cve_id][1].get(vuln, set())
            return patches
        return set()

    def remove_mapping(self, cve_id: str, patch: Patch_Commit, vuln: Vuln_Commit) -> None:
        """Removes a specific patch-vulnerability relationship for the given CVE ID."""
        if cve_id in self._cve_mapping:
            # Remove patch -> vuln relationship
            if patch in self._cve_mapping[cve_id][0]:
                self._cve_mapping[cve_id][0][patch].discard(vuln)
                if not self._cve_mapping[cve_id][0][patch]:  # Remove empty entries
                    del self._cve_mapping[cve_id][0][patch]

            # Remove vuln -> patch relationship
            if vuln in self._cve_mapping[cve_id][1]:
                self._cve_mapping[cve_id][1][vuln].discard(patch)
                if not self._cve_mapping[cve_id][1][vuln]:  # Remove empty entries
                    del self._cve_mapping[cve_id][1][vuln]

    def get_all_mappings(self):
        """Returns the full bidirectional mapping for all CVE IDs."""
        return self._cve_mapping

    
class CVE(BaseModel):
    """
    A CVE instance should contain everything. Vuln classifier, vuln commits, patch commits
    Args:
        Vulnerability_Classifier (_type_): _description_
        Vuln_Commits (_type_): _description_
    """
    
    def __init__(self,cve_id: str, partial_repo_path: str, hash_patch_commit:str, config: setup.SCRIPT_CONFIG,patch_vuln_bi_map: PatchVulnBiMap) -> None:
        
        # I need to get the full repo path from the partial repo path 
        # the full repo path is the path on the super computer
        # create a partial repo path field
        # and full repo path field!

        super().__init__() # Calls the next class in MRO

        ### Bi-Directional Map used to keep track of relationships of all CVE's ###
        self._patch_vuln_bi_map:PatchVulnBiMap = patch_vuln_bi_map ### Dependency injection is being used

        ### CVE Info ###
        ############################################################################
        self._cve_id: str = cve_id

        ### Repo Info ###
        ############################################################################
        
        self._partial_repo_path: str = partial_repo_path
        self._full_repo_path: str = self.get_full_repo_path(partial_repo_path,config) ### Dependency injection is being used

        
        self._commits_up_to_patch: Generator = Repository( # Get all commits up to the patch commit (define order)
                                                            self._full_repo_path,
                                                            single = hash_patch_commit,
                                                            to_commit = hash_patch_commit).traverse_commits()

        commit_hash_obj: Commit = self.create_patch_commit_obj(patch_commit_hash=hash_patch_commit)

        self._primary_patch_commit: Patch_Commit = Patch_Commit(self._full_repo_path,commit_hash_obj)
        
        ###  Add first patch commit to the Bi Map ###
        ### Don't have a vuln commit to add yet ###
        self.__class__.add_to_BiMap(cve_id=cve_id,patch_commit=self._primary_patch_commit)

    
    

    ### Bi-Map Helper Methods ###
    ############################################################################

    def get_patch_for_cve_id(self,cve_id: str) -> Optional[Patch_Commit]:

        if cve_id in self._patch_vuln_bi_map:
            pass

    def add_to_BiMap(self,**kwargs)->None:
        """
        This function is used when a cve id appears twice in the json file which implies multiple patch commits for a single cve.
        Args:
           
        """

        cve_id: str = kwargs.get("cve_id",None)
        patch_commit: Patch_Commit = kwargs.get("patch_commit", None)
        vuln_commit: Vuln_Commit = kwargs.get("vuln_commit", None)

        ### Where everyting is being added to the map ###
        self._patch_vuln_bi_map.add_mapping(cve_id,patch=patch_commit,vuln=vuln_commit)

    def get_vulns_for_patch(self,cve_id: str, patch: Patch_Commit) -> None:
        
        return self._patch_vuln_bi_map.get_vulns_for_patch(self._patch_vuln_bi_map,cve_id,patch)
    def get_patches_for_vuln(self,cve_id: str, vuln: Vuln_Commit) -> None:
        return self._patch_vuln_bi_map.get_patches_for_vuln(self._patch_vuln_bi_map,cve_id,vuln)
    
    
    def remove_mapping(self, cve_id: str, patch: Patch_Commit, vuln: Vuln_Commit) -> None:
        self._patch_vuln_bi_map.remove_mapping(cve_id,patch,vuln)
    
    
    def get_all_cve_mappings(self):
        return self._patch_vuln_bi_map.get_all_mappings(self._patch_vuln_bi_map)


    def create_patch_commit_obj(self,patch_commit_hash:str) -> Patch_Commit:
        commit_obj: Commit = next(Repository( # Only get the hash patch commit object
                                                                self._full_repo_path,
                                                                single = patch_commit_hash).traverse_commits())
        
        patch_commit_obj: Patch_Commit = Patch_Commit(self._full_repo_path,commit_obj)
        
        return patch_commit_obj
    
    def create_vuln_commit_obj(self,vuln_commit_hash:str, patch_commit_obj: Patch_Commit) -> Vuln_Commit:
        commit_obj: Commit = next(Repository( # Only get the hash Vuln commit object
                                                                self._full_repo_path,
                                                                single = vuln_commit_hash).traverse_commits())
        
        vuln_commit_obj: Vuln_Commit = Vuln_Commit(self._full_repo_path,vuln_commit_obj=commit_obj,)
        
        return vuln_commit_obj
    
    def get_full_repo_path(partial_repo_path: str, config: setup.SCRIPT_CONFIG) -> str:
        """
        Use the global config ROOT DIR field to get to the specific repo for the project. 
        Make sure that there is a .git! That's a little check that can go a long way.
        Args:
            partial_repo_path (str): _description_

        Returns:
            str: _description_
        """
        pass
    
    def compare_patch_and_vuln_modifications():
        """
        Previously, the issue has been: How do you prove that you found the vulnerability with a specific
        percentage of accuracy. 

        Below we're going to do that! If anything differs (caveat some things can differ like file path because things change), 
        we know we don't have the correct commit that introduced the vulnerability.

        *** How do I develop a probability prediction metric system? *** I want to know with a certain degree of confidence
        that the vuln commit/ commits are in fact what I went looking for.

        Ex: 
        - modified files: patch commit could be doing more than just fixing the vuln. But if some of the vuln modified files are in 
        the list of modified files by the patch commit, then we're cooking! 

        - basically compare all of the fields present in the Commit and Vuln classifiers contextually.
        """
        pass
    def compaure_patch_and_vuln_complexity():
        pass

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
    def _commits_up_to_patch(self) -> Generator:
        return self._commits_up_to_patch
    
    @_commits_up_to_patch.setter
    def _commits_up_to_patch(self,value:Generator) -> None:
        self._commits_up_to_patch = value
    
    @property
    def _primary_patch_commit(self) -> Commit:
        return self._primary_patch_commit

    @_primary_patch_commit.setter
    def _primary_patch_commit(self, value: Commit) -> None:
        self._primary_patch_commit = value

    