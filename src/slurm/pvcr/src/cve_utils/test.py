from collections import defaultdict


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


def main():
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


if __name__ == "__main__":
    main()