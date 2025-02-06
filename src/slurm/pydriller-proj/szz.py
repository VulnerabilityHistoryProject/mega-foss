

import logging
import sys
from typing import Any, Type, Dict,Optional
from pydriller import ModifiedFile, Git, Commit
import error_handling as handle


def find_modified_files(patch_commit_hash: str = "", selected_repo: str = "") -> set[ModifiedFile]:
    """
    Given a specific patch commit hash and a repo corresponding to the FOSS project, via a path, returns a set of ModifiedFile objects. 
    All items in the set are modified files by the patch commit hash.

    Args:
        patch_commit_hash (str, optional): The hash to be analyzed. Defaults to HASH_PATCH_COMMIT.
        selected_repo (str, optional): Path to repo used to analyze a commit hash. Defaults to PATH_SELECTED_REPO.

    Returns:
        set[ModifiedFile]: Set of ModifiedFile objects that were all modified by the patch commit to eliminate the CVE.
    """
    # Create an empty set for files that were modified by the patch commit
    modified_file_objects: set[ModifiedFile] = set()


    # Assign global variables with more control
    patch_commit_hash: str = handle.get_global_variable("HASH_PATCH_COMMIT", str)
    selected_repo: str = handle.get_global_variable("PATH_SELECTED_REPO", str)
    
    # Get Git object and get the commit objects
    selected_git_repo_obj: Git = handle.git_repo_conversion(selected_repo) 
    patch_commit_obj: Commit = handle.fetch_commmit_obj(selected_git_repo_obj,patch_commit_hash)


    for modified_file_obj in patch_commit_obj.modified_files:

        if handle.validate_modified_file(modified_file_obj) == False:
            continue
        

        try: # add to the set 
            modified_file_objects.add(modified_file_obj)
        
        except Exception as e:
            logging.error(f"Unexpected error while processing file '{modified_file_obj}': {e} for {patch_commit_hash} in {selected_repo}")


    globals().get()
    return modified_file_objects


def track_commit_changes(modified_file_obj: ModifiedFile) -> None:
    """
    Tracks the added and deleted code in a modified file. Stores the changes in the global variable
    CHANGES_PATCH_COMMIT dictionary.

    Args:
        modified_file_obj (ModifiedFile): This is a file that was modified by a patch commit, vulnerability commit, or general commit.
    """
    
    handle.validate_modified_file(modified_file_obj)

    # Access validated attributes
    old_path: str = modified_file_obj.old_path
    diff_parsed: dict = modified_file_obj.diff_parsed

    # Update the CHANGES_PATCH_COMMIT dictionary
    CHANGES_PATCH_COMMIT: dict = handle.get_global_variable("CHANGES_PATCH_COMMIT", dict)
    handle.safe_dict_set(CHANGES_PATCH_COMMIT, old_path, diff_parsed)