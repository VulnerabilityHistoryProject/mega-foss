from typing import Any,Generator, Optional, ClassVar
from collections import defaultdict
### pydriller imports ###
from pydriller import Repository, Commit, ModifiedFile


### In the same directory ###
from cve import CVE
from cve_utils.patch_commit import Patch_Commit
from cve_utils.parent_commit import Parent_Commit


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
                                   dict[Patch_Commit, set[Parent_Commit]],  # patch -> vuln mapping
                                   dict[Parent_Commit, set[Patch_Commit]]   # vuln -> patch mapping
                               ]] = {}
        
        
        
        
        
        
        
        '''
        I need a way to create a patch commit and associate it with a particular cve id
        without creating an entire cve object


        each cve_id needs to have the potential to connect to multiple patch commits

        every patch commit needs to have corresponding parent commits
        every patch commit needs to have corresponding vuln commits (I'm thinking confidence levels)
        every vuln commit needs 

        idea: group parent commits based on confidence level. Then use those confidence intervals as some sort of data structure for quick lookup

        
        '''

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




class CVECommitMapping:
    def __init__(self):
        # Initialize the data structure to store CVE -> Confidence Level -> Patch Commit -> Parent Commits
        self.cve_commit_mapping = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))  

    def add_parent_commit(self, cve_id, patch_commit, parent_commit, confidence_level):
        """
        Add a parent commit to a specific CVE ID and patch commit with a given confidence level.

        Args:
        - cve_id (str): The CVE ID.
        - patch_commit (str): The patch commit ID.
        - parent_commit (str): The parent commit ID.
        - confidence_level (str): The confidence level for this parent commit.
        """
        self.cve_commit_mapping[cve_id][confidence_level][patch_commit].add(parent_commit)

    def move_parent_commit_to_another_confidence(self, cve_id, patch_commit, parent_commit, old_confidence, new_confidence):
        """
        Move a parent commit from one confidence level to another for a given CVE ID and patch commit.

        Args:
        - cve_id (str): The CVE ID.
        - patch_commit (str): The patch commit ID.
        - parent_commit (str): The parent commit ID.
        - old_confidence (str): The old confidence level.
        - new_confidence (str): The new confidence level.
        """
        # Remove the parent commit from the old confidence level
        if parent_commit in self.cve_commit_mapping[cve_id][old_confidence][patch_commit]:
            self.cve_commit_mapping[cve_id][old_confidence][patch_commit].remove(parent_commit)
        
        # Add the parent commit to the new confidence level
        self.cve_commit_mapping[cve_id][new_confidence][patch_commit].add(parent_commit)

    def get_patch_commits_for_cve(self, cve_id, confidence_level):
        """
        Get all patch commits associated with a given CVE ID and confidence level.

        Args:
        - cve_id (str): The CVE ID.
        - confidence_level (str): The confidence level.
        
        Returns:
        - dict: A dictionary of patch commits and their associated parent commits.
        """
        return self.cve_commit_mapping[cve_id][confidence_level]

    def get_all_parent_commits_for_patch(self, cve_id, patch_commit):
        """
        Get all parent commits for a given patch commit across all confidence levels.

        Args:
        - cve_id (str): The CVE ID.
        - patch_commit (str): The patch commit ID.
        
        Returns:
        - dict: A dictionary of confidence levels and associated parent commits.
        """
        parent_commits = {}
        for confidence_level, patch_data in self.cve_commit_mapping[cve_id].items():
            if patch_commit in patch_data:
                parent_commits[confidence_level] = patch_data[patch_commit]
        return parent_commits

    def get_cve_id_for_commit(self, commit):
        """
        Retrieve the CVE ID associated with a given commit.

        Args:
        - commit (str): The commit ID (patch or parent).
        
        Returns:
        - str: The associated CVE ID.
        """
        # Iterate through the mapping to find the CVE ID for the given commit
        for cve_id, confidence_levels in self.cve_commit_mapping.items():
            for confidence_level, patch_commits in confidence_levels.items():
                for patch_commit, parent_commits in patch_commits.items():
                    if commit == patch_commit or commit in parent_commits:
                        return cve_id
        return None





if __name__ == "__main__":
    bimap = PatchVulnBiMap()
    # Example usage
    cve_mapping = CVECommitMapping()

    # Adding parent commits with different confidence levels for the same patch commit
    cve_mapping.add_parent_commit('CVE-1234', 'patch1', 'parent1', '0-25%')
    cve_mapping.add_parent_commit('CVE-1234', 'patch1', 'parent2', '26-50%')
    cve_mapping.add_parent_commit('CVE-1234', 'patch1', 'parent3', '50-75%')

    # Retrieve all parent commits for a given patch commit
    print(cve_mapping.get_all_parent_commits_for_patch('CVE-1234', 'patch1'))
    # Output: {'0-25%': {'parent1'}, '26-50%': {'parent2'}, '50-75%': {'parent3'}}

    # Move a parent commit to another confidence level
    cve_mapping.move_parent_commit_to_another_confidence('CVE-1234', 'patch1', 'parent1', '0-25%', '50-75%')

    # Retrieve updated parent commits for the given patch commit
    print(cve_mapping.get_all_parent_commits_for_patch('CVE-1234', 'patch1'))
    # Output: {'26-50%': {'parent2'}, '50-75%': {'parent1', 'parent3'}}

    # Get the CVE ID for a given parent commit
    print(cve_mapping.get_cve_id_for_commit('parent1'))  # Output: CVE-1234