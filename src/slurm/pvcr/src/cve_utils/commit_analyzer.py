from pydriller import Commit


### 
from patch_commit import Patch_Commit
from parent_commit import Parent_Commit
class Commit_Analyzer:
    """
    This will take in a patch commit, and a list of parent commits.

    Each parent commit will be given a confidence score based on several metrics and one will be crowned the winner!!!

    """

    ### I analyze the parents against the patch here! So this is where I would derive the confidence

    def __init__(self, patch_commit: Patch_Commit, parent_commits: list[Parent_Commit]) -> None:


        ### Challenge is match all of the changes from all 6 parent commits (5 parents + genesis commit) to the one patch commit
        self._changes_parent_commits: list[dict]
        self._changes_patch_commit: dict = None
        pass
        
    def analyze_lines_changed(self,_base_commit_obj: Commit) -> bool:
        pass
    
    def analyze_functions_changed(self,_base_commit_obj:Commit) -> bool:
        pass
    pass