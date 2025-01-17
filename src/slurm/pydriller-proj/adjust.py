from pydriller import Git

FIXED_VULN_COMMIT_HASH: str = "54e488b9da4abbceaf405d6492515697"
FFMPEG_PATH_TO_REPO: str = "/path/to/ffmpeg/repo"  # Update this
MODIFIED_FILES: set[str] = set()

def find_origin_commit(fixed_commit_hash: str = FIXED_VULN_COMMIT_HASH, repo_path: str = FFMPEG_PATH_TO_REPO) -> set[str]:
    """
    Find the files modified by the commit that fixed the vulnerability.

    Args:
        fixed_commit_hash (str): The hash of the commit fixing the vulnerability.
        repo_path (str): Path to the repository.

    Returns:
        set[str]: Set of modified file paths.
    """
    modified_file_paths_from_fix: set = set()

    # Initialize the Git repository
    ffmpeg_git_repo = Git(repo_path)

    # Get the commit object for the fixed commit
    fixed_commit = ffmpeg_git_repo.get_commit(fixed_commit_hash)

    # Collect the modified file paths
    for modified_file in fixed_commit.modified_files:
        path = modified_file.old_path or modified_file.new_path
        modified_file_paths_from_fix.add(path)

    return modified_file_paths_from_fix





if __name__ == "__main__":
    
