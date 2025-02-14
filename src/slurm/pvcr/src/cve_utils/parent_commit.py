


### Pydriller
from pydriller import Commit, ModifiedFile
from vulnerable_commit import Vuln_Confidence

class Parent_Commit():
    """
    This is the class that creates the 5 previous parent commits relative to the patch commit
        
    """

    def __init__(self, full_repo_path: str, base_commit_obj: Commit) -> None:
        super().__init__() # Calls the next class in MRO
        
        self._full_repo_path: str = full_repo_path
        self._base_commit_obj: Commit = base_commit_obj ### Generic Commit Prior to being converted into a Vuln Commit object ###

        # Create an instance of Parent_Commit_Classifier and associate it with this Parent_Commit instance
        self._classifier: Parent_Commit_Classifier = Parent_Commit_Classifier(base_commit_obj)

        


        # Call the classifier method to update fields based on the Vuln commit object
        self._classifier.classify_vuln_commit_basic(base_commit_obj,)
        '''create function above so that it exists'''


        self._confidence_level: Vuln_Confidence = Vuln_Confidence(self._classifier) ### Use classifier to quantify confidence level
       
    
    def __eq__(self, other:object):
        return isinstance(other,Vuln_Commit) and self._base_commit_obj.hash == other._base_commit_obj.hash

    def __hash__(self):
        return hash(self._base_commit_obj.hash)
    
    def get_classifier_info(self, basic: bool = True, advanced: bool = False) -> dict:

        """
        Returns a dictionary containing classifier-related information.
        """

        basic: dict[str, Any] = {
            "adds_code": self._classifier._adds_code,
            "deletes_code": self._classifier._deletes_code,
            "changes_lines": self._classifier._changes_lines,
            "changes_functions": self._classifier._changes_functions,
            "changes_files": self._classifier._changes_files,
            "is_prev_commit_to_patch": self._classifier._is_prev_commit_to_patch,
            "number_of_patch_commits_for_vuln": self._classifier._number_of_patch_commits_for_vuln,
            "dmm_unit_size": self._classifier._dmm_unit_size,
            "dmm_unit_complexity": self._classifier._dmm_unit_complexity,
            "dmm_unit_interfacing": self._classifier._dmm_unit_interfacing
        }
        advanced: dict[str,Any] = {
            
            "refactors_code": self._classifier._refactors_code,
            "was_patch_partial_fix": self._classifier._was_patch_partial_fix,
        
        }

        if basic and advanced:
            return basic.update(advanced) ### Add dictionaries together ###
        elif basic:
            return basic
        elif advanced:
            return advanced
        else:
            return None
    
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
    def classifier_(self) -> "Parent_Commit_Classifier": ### Forward Declaration ###
        return self._classifier
    
class Parent_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the vulnerability?

    Classify's vulnerability based on factors related to implementation and severity
    """
    def __init__(self,base_commit_obj: Commit) -> None:

        super().__init__() # Calls the next class in MRO
        """ """
        
        self._base_commit_obj: Commit = base_commit_obj
    
        
        ### Get Modified Files & Modified File Types  ###
        self._mod_files_by_parent_commit: list[ModifiedFile] = [] 
        self._mod_files_by_parent_commit.extend(self._base_commit_obj.modified_files) 
        self._modified_file_types: set[str] = self.get_modified_file_types(self._mod_files_by_parent_commit)
     
       
        

        self._initialize_fields(self,self._base_commit_obj, self._mod_files_by_vuln_commit)


        self._VULN_CONFIDENCE: float = 0.0

        self._analyzer = Parent_Commit_Analyzer()
        '''
        DECIDE WHAT FIELDS TO USE
        
        '''

    def get_modified_file_types(self, modified_files_by_parent_commit: list[ModifiedFile]) -> set[str]:
        # Regex pattern to capture file extensions
        extension_pattern = r'\.[a-zA-Z0-9]+$'
        
        # Create a set to store unique file extensions
        file_types = set()

        # Iterate through modified files and extract the extensions
        for file in modified_files_by_parent_commit:
            match = re.search(extension_pattern, file.filename)
            if match:
                file_types.add(match.group(0))  # Add the file extension with dot

        return file_types

    def _initialize_fields(self, base_commit_obj: Commit, modified_files_by_vuln_commit: list[ModifiedFile]) -> None: 
        self.classify_vuln_commit_basic(base_commit_obj,modified_files_by_vuln_commit)
        

        ### For a later time
        # self.classify_vuln_commit_advanced(_base_commit_obj, modified_files_by_vuln_commit)

    def classify_vuln_commit_basic(self, base_commit_obj: Commit, modified_files_by_vuln_commit: list[ModifiedFile]) -> None:
        
        #### Used for comparing Patch Commit to Vuln Commit ###
        ### Classifications for V1 ###
        self._adds_code: bool = base_commit_obj.insertions > 0
        self._deletes_code: bool = base_commit_obj.deletions > 0

        self._changes_lines: bool = bool(self._adds_code or self._deletes_code)
        self._changes_files: bool = len(modified_files_by_vuln_commit) > 1

        ### Unique to Parent Commits ###
        ### Is the commit that directly preceeded the patch commit? ###
        self._is_father_commit: bool

        ### Is the genesis commit ###
        ### This means that from this commit you can't go back any farther with blames or anything else. It started the file / project. ###
        self._is_genesis_commit: bool

        for file in modified_files_by_vuln_commit:
            self._changes_functions: bool = len(file.changed_methods) > 0


        
        
        ### this is gonna take a bit more work to define than I initially thought
        self._is_prev_commit_to_patch = False


        ### lookup in the map
        self._number_of_patch_commits_for_vuln: int = 1 # Sometimes multiple patches are needed to fix a single vuln


        ### Complexity ### 
        self._dmm_unit_size: float = None
        self._dmm_unit_complexity: float = None
        self._dmm_unit_interfacing: float = None
        #######################################################

    def classify_vuln_commit_advanced(self, base_commit_obj: Commit) -> None:
        ### Classifications for V2 ###
        self._refactors_code: bool = False
        self._was_patch_partial_fix: bool = False # did the patch only partially fix this vuln? True if num of patch commits (field below is greater than 1)


    @property
    def _base_commit_obj(self) -> Commit:
        return self._base_commit_obj

    @property
    def _modified_files_by_vuln_commit(self) -> list[ModifiedFile]:
        return self._modified_files_by_vuln_commit
    ### Code for V2 ###
    def vuln_refactors_code(self,_base_commit_obj) -> bool:
        pass
    def vuln_hash_partial_patch_commit_fixes() -> bool:
        pass

