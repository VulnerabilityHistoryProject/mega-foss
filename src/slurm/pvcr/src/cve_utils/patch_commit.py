from typing import Any,Generator, Optional, ClassVar
from pydantic import BaseModel
import re
from datetime import datetime

### In the same directory ###
from cve import CVE
from cve_utils.patch_parent_nexus import PatchVulnBiMap


### pydriller imports ###
from pydriller import Repository, Commit, ModifiedFile


class Patch_Commit():
    """
    All the data to capture from the Patch commits
    """
    def __init__(self, full_repo_path: str, base_commit_obj:Commit) -> None:

        super().__init__()

        self._full_repo_path: str = full_repo_path
        self._base_commit_obj: Commit = base_commit_obj ### Generic Commit Prior to being converted into a Patch Commit Object ###
        self._mod_files_by_patch_commit: list[ModifiedFile] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        self._date_created: datetime
        
        self._changes_by_patch_commit: dict = {}

        # Create an instance of Patch_Commit_Classifier and associate it with this Patch_Commit instance
        self._classifier: Patch_Commit_Classifier = Patch_Commit_Classifier()

        # Call the classifier method to update fields based on the patch commit object
        self._classifier.classify_patch_commit(base_commit_obj)

        ### Changes Made By Patch Commit ###
        self._mod_files_by_patch_commit.extend(base_commit_obj.modified_files) 
    
    def __eq__(self, other:object):
        return isinstance(other,Patch_Commit) and self._base_commit_obj.hash == other._base_commit_obj.hash

    def __hash__(self):
        return hash(self._base_commit_obj.hash)
    
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


    @property
    def full_repo_path(self) -> str:
        return self._full_repo_path

    @property
    def base_commit_obj(self) -> Commit:
        return self._base_commit_obj

    @property
    def mod_files_by_patch_commit(self) -> list[ModifiedFile]:
        return self._mod_files_by_patch_commit

    @property
    def changes_by_patch_commit(self) -> dict:
        return self._changes_by_patch_commit
    @property
    def classifier(self) -> "Patch_Commit_Classifier": ### Forward declaration ###
        return self._classifier

class Patch_Commit_Classifier(BaseModel):
    """
    The goal of this class is to answer the question: What has been changed by the patch commit??
    """
    def __init__(self) -> None:
        super().__init__() # Calls the next class in MRO
       
        self._analyzer = Patch_Commit_Analyzer()
       
        ### TO-DO ###
        # Continue reading papers to refine this list of fieds
        self._adds_code: bool = False
        self._deletes_code: bool = False
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

