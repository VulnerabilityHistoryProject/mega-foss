class Patch_Commit_Classifier:
    """
    The goal of this class is to answer the question: What has been changed by the patch commit??
    """
    def __init__(self) -> None:
        # Initialize fields
        self._adds_code: bool = False
        self._deletes_code: bool = False
        self._refactors_code: bool = False
        self._changes_lines: bool = False
        self._changes_functions: bool = False
        self._changes_files: bool = False
        self._patch_partial_fix: bool = False
        self._number_of_vulns_fixed_by_patch: int = 1

    # Example method to update the classifier fields based on some logic
    def classify_patch(self, patch_commit_hash_obj):
        # Update the fields based on the patch commit analysis (simplified here)
        self._adds_code = patch_commit_hash_obj.insertions > 0
        self._deletes_code = patch_commit_hash_obj.deletions > 0
        self._changes_lines = len(patch_commit_hash_obj.modified_files) > 0
        # You can add further logic based on your needs
        # For example:
        self._number_of_vulns_fixed_by_patch = len(patch_commit_hash_obj.modified_files)  # Example logic

class Patch_Commit:
    """
    All the data to capture from the Patch commits
    """
    def __init__(self, full_repo_path: str, patch_commit_hash_obj) -> None:
        self._fulle_repo_path: str = full_repo_path
        self._patch_commit_hash_obj = patch_commit_hash_obj
        
        # Create an instance of Patch_Commit_Classifier and associate it with this Patch_Commit instance
        self.classifier = Patch_Commit_Classifier()

        # Call the classifier method to update fields based on the patch commit object
        self.classifier.classify_patch(patch_commit_hash_obj)

        # Additional fields related to Patch_Commit
        self._mod_files_by_patch_commit: list[str] = []  # Ordered list for modified files
        self._changes_by_patch_commit: dict = {}  # Dictionary for changes (can be expanded based on logic)

    def get_classifier_info(self):
        # Return the information from the classifier if needed
        return {
            "adds_code": self.classifier._adds_code,
            "deletes_code": self.classifier._deletes_code,
            "changes_lines": self.classifier._changes_lines,
            "number_of_vulns_fixed_by_patch": self.classifier._number_of_vulns_fixed_by_patch,
        }

# Example of usage
patch_commit = Patch_Commit("some_repo_path", patch_commit_hash_obj)
print(patch_commit.get_classifier_info())
