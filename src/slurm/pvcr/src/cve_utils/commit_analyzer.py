from pydriller import Commit


class Commit_Analyzer:
    """
    This will take in a patch commit, and a list of parent commits.

    Each parent commit will be given a confidence score based on several metrics and one will be crowned the winner!!!

    """

    def __init__(self,):
        pass
        
    def analyze_lines_changed(self,_base_commit_obj: Commit) -> bool:
        pass
    
    def analyze_functions_changed(self,_base_commit_obj:Commit) -> bool:
        pass
    pass