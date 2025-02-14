from typing import Any,Generator, Optional, ClassVar

### pydriller imports ###
from pydriller import Repository, Commit, ModifiedFile


### In the same directory ###
from cve import CVE
from cve_utils.patch_commit import Patch_Commit, Vuln_Commit


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



if __name__ == "__main__":
    bimap = PatchVulnBiMap()