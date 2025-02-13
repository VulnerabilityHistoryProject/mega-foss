



class Patch_Commit():
    """
    All the data to capture from the Patch commits
    """
    def __init__(self, full_repo_path: str, _base_commit_obj:Commit) -> None:

        super().__init__() # Calls the next class in MRO

        self._full_repo_path: str = full_repo_path


        self._base_commit_obj: Commit = base_commit_obj ### Generic Commit Prior to being converted into a Patch Commit Object ###


        self._mod_files_by_patch_commit: list[ModifiedFile] = [] ### This list needs to be "ordered" so that order in which files are changed is maintained
        
        
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

class Vuln_Commit():
    """
    Every Vulnerable Commit has a corresponding patch commit to go along with it.
    There can also be multiple vulns that correspond to a single patch commit
    Args:

    ### I want each vulnerable commit to have a classifier for that commit!! ###
        
    """

    
    def __init__(self, full_repo_path: str, base_commit_obj: Commit) -> None:
        super().__init__() # Calls the next class in MRO
        
        self._full_repo_path: str = full_repo_path


        self._base_commit_obj: Commit = base_commit_obj ### Generic Commit Prior to being converted into a Vuln Commit object ###

        
        self._mod_files_by_vuln_commit: list[ModifiedFile] = []
        
        
        self._changes_vuln_commit: dict = {}

        # Create an instance of Vuln_Commit_Classifier and associate it with this Vuln_Commit instance
        self._classifier = Vuln_Commit_Classifier()

        # Call the classifier method to update fields based on the Vuln commit object
        self._classifier.classify_vuln_commit(base_commit_obj)

        ### Changes Made By Patch Commit ###
        self._mod_files_by_vuln_commit.extend(base_commit_obj.modified_files) 
    
    def __eq__(self, other:object):
        return isinstance(other,Vuln_Commit) and self._base_commit_obj.hash == other._base_commit_obj.hash

    def __hash__(self):
        return hash(self._base_commit_obj.hash)
    
    def get_classifier_info(self) -> dict:

        """
        Returns a dictionary containing classifier-related information.
        """
        return {
            "adds_code": self._classifier._adds_code,
            "deletes_code": self._classifier._deletes_code,
            "refactors_code": self._classifier._refactors_code,
            "changes_lines": self._classifier._changes_lines,
            "changes_functions": self._classifier._changes_functions,
            "changes_files": self._classifier._changes_files,
            "patch_partial_fix": self._classifier._patch_partial_fix,
            "number_of_vulns_fixed_by_patch": self._classifier._number_of_vulns_fixed_by_patch,
            "dmm_unit_size": self._classifier._dmm_unit_size,
            "dmm_unit_complexity": self._classifier._dmm_unit_complexity,
            "dmm_unit_interfacing": self._classifier._dmm_unit_interfacing,
        }
    
    @property
    def full_repo_path(self) -> str:
        return self._full_repo_path

    @property
    def base_commit_obj(self) -> Commit:
        return self._base_commit_obj

    @property
    def mod_files_by_vuln_commit(self) -> list[ModifiedFile]:
        return self._mod_files_by_vuln_commit

    @property
    def changes_vuln_commit(self) -> dict:
        return self._changes_vuln_commit
    @property
    def classifier_(self) -> "Vuln_Commit_Classifier": ### Forward Declaration ###
        return self._classifier
    
class Vuln_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the vulnerability?
    """
    def __init__(self,base_commit_obj: Commit) -> None:

        super().__init__() # Calls the next class in MRO
        """ Classify's vulnerability based on factors related to implementation and severity"""
        ### TO-DO ###
        # Continue reading papers to refine this list of fieds
        self._base_commit_obj: Commit = base_commit_obj
        self._initialize_fields(self,self._base_commit_obj)
        

       
    def _initialize_fields(self, _base_commit_obj: Commit) -> None: 
        self.classify_vuln_commit_basic(self,_base_commit_obj)

    def classify_vuln_commit_basic(self, _base_commit_obj: Commit) -> None:
        
        #### Used for comparing Patch Commit to Vuln Commit ###
        ### Classifications for V1 ###
        self._adds_code: bool = _base_commit_obj.insertions > 0
        self._deletes_code: bool = _base_commit_obj.deletions > 0
        
        if self._adds_code or self._deletes_code:
            self._changes_lines: bool = True

        _base_commit_obj.modified_files
        
        self._changes_functions: bool = False
        self._changes_files: bool = False
        self._is_prev_commit_to_patch = False
        self._number_of_patch_commits_for_vuln: int = 1 # Sometimes multiple patches are needed to fix a single vuln


        ### Complexity ### 
        self._dmm_unit_size: float = None
        self._dmm_unit_complexity: float = None
        self._dmm_unit_interfacing: float = None
        #######################################################

    def classify_vuln_commit_advanced(self, _base_commit_obj: Commit) -> None:
        ### Classifications for V2 ###
        self._refactors_code: bool = False
        self._was_patch_partial_fix: bool = False # did the patch only partially fix this vuln? True if num of patch commits (field below is greater than 1)


    def vuln_changes_lines(self,_base_commit_obj: Commit) -> bool:
        pass
    
    def vuln_changes_functions(self,_base_commit_obj:Commit) -> bool:
        pass

    
    ### Classifications for V2 ###
    def vuln_refactors_code(self,_base_commit_obj) -> bool:
        pass
    def vuln_hash_partial_patch_commit_fixes() -> bool:
        pass

    @property
    def _base_commit_obj(self) -> Commit:
        return self._base_commit_obj