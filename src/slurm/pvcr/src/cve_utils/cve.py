import logging
import os
import sys
from typing import Any,Generator, Optional, ClassVar
from pydantic import BaseModel

### pydriller imports ###
from pydriller import Repository, Commit, ModifiedFile


### Project imports ###
from error_handling import handle_errors as handle
from szz_utils import szz
from configuration.script_setup import SCRIPT_CONFIG


### In the same directory ###
from patch_vuln_commit import Patch_Commit, Vuln_Commit, Commit_Analyzer
from BiMap import PatchVulnBiMap


class CVE(BaseModel):
    """
    A CVE instance should contain everything. Vuln classifier, vuln commits, patch commits
    Args:
        Vulnerability_Classifier (_type_): _description_
        Vuln_Commits (_type_): _description_
    """
    
    def __init__(self,cve_id: str, partial_repo_path: str, patch_commit_hash: str, config: SCRIPT_CONFIG,patch_vuln_bi_map: PatchVulnBiMap) -> None:
        
        # I need to get the full repo path from the partial repo path 
        # the full repo path is the path on the super computer
        # create a partial repo path field
        # and full repo path field!

        super().__init__() # Calls the next class in MRO

        ### Bi-Directional Map used to keep track of relationships of all CVE's ###
        self._patch_vuln_bi_map: PatchVulnBiMap = patch_vuln_bi_map ### Dependency injection is being used
        
        
        ### Each CVE object will have its own patch vuln analyzer ###
        self._patch_vuln_analyzer: Commit_Analyzer = Commit_Analyzer()


        ### CVE Info ###
        ############################################################################
        self._cve_id: str = cve_id

        ### Repo Info ###
        ############################################################################
        
        self._partial_repo_path: str = partial_repo_path
        self._full_repo_path: str = self.get_full_repo_path(partial_repo_path,config) ### Dependency injection is being used

        ### Parent Commits --> BINGO ###
        '''
        self._commits_up_to_patch: Generator = Repository( # Get all commits up to the patch commit (define order)
                                                            self._full_repo_path,
                                                            single = patch_commit_hash, 
                                                            to_commit = patch_commit_hash).traverse_commits()
        ''' ### code for another time
            
        
        generate_parent_commits(commits_up_to_patch) ### Creates the parent commits objects and adds them to the


        commit_hash_obj: Commit = self.create_patch_commit_obj(patch_commit_hash) 

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

    ### Bi-Map Helper Methods Done ###
    ############################################################################
    
    def generate_parent_commits(commits_up_to_patch: Generator[Commit]) -> None:
        """

        I could do a lot of things here... I coule use git bisect to figure out which commits are worth 
        turning into commit objects... But that might be a lot of work anyway so it might make sense to just 
        turn them all into parent commits

        Args:
            commits_up_to_patch (Generator[Commit]): _description_
        """
        pass

    def create_base_commit_obj(self, commit_hash: str) -> Commit:
        commit_obj: Commit = next(Repository( # Only get the hash patch commit object
                                                                self._full_repo_path,
                                                                single = commit_hash).traverse_commits())
        return commit_obj
    def create_patch_commit_obj(self,commit_obj: Commit) -> Patch_Commit:
        patch_commit_obj: Patch_Commit = Patch_Commit(self._full_repo_path,patch_commit_obj=commit_obj)

        return patch_commit_obj
    
    def create_vuln_commit_obj(self,commit_obj: Commit) -> Vuln_Commit:
        vuln_commit_obj: Vuln_Commit = Vuln_Commit(self._full_repo_path,vuln_commit_obj=commit_obj)
        
        return vuln_commit_obj
    
    def get_full_repo_path(partial_repo_path: str, config: SCRIPT_CONFIG) -> str:
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

        #### Maybe I can write a __eq__ method that does the calculations betwen
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

    