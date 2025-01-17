#!/usr/bin/env python3
"""
Module Name: VHP_ffmpeg.py

Description:
    This python script is to be used on the RIT Research Computing Cluster to analyze CVE-2015-8218
    via this commit hash:54e488b9da4abbceaf405d6492515697. This hash it the commit of the patch for 
    this vulnerability. This file will mainly depend on pydriller to locate the original commit that 
    caused this vulnerability.This vulnerability had to deal with an overlooked array of some sort.

Author: Trust-Worthy, TylerJaafari-RIT

Date: 2025-1-17 
    
    
Notes: 
    - pydriller must be installed on the system to run this program

"""


from pydriller import Repository
from pydriller.metrics.process.change_set import ChangeSet
from pydriller import Git
import subprocess as subsub

FIXED_VULN_COMMIT_HASH:str = "54e488b9da4abbceaf405d6492515697"
ORIGIN_COMMIT_HASH:str = ""
FFMPEG_PATH_TO_REPO:str = ""
MODIFIED_FILES:set[str] = set()





def find_origin_commit(fixed_commit_hash:str = FIXED_VULN_COMMIT_HASH, repo_path:str = FFMPEG_PATH_TO_REPO) -> None:
    """_summary_

    Args:
        fixed_commit_hash (str, optional): _description_. Defaults to FIXED_VULN_COMMIT_HASH.
        repo_path (str, optional): _description_. Defaults to FFMPEG_PATH_TO_REPO.
    """
    global MODIFIED_FILES
    
    # Create empty set for files that were modified by the fixed commit
    modified_file_paths_from_fix:set = set()

    # converting path to a Git object --> ffmpeg git repo
    ffmpeg_git_repo= Git(repo_path)

    # Getting the commit object from the fixed commit hash the fixed the vulnerability
    fixed_commit = ffmpeg_git_repo.get_commit(fixed_commit_hash)


    # Add modified files to the set for later reference
    for modified_file in fixed_commit.modified_files:

        path:str = ""

        if modified_file.old_path == modified_file.new_path: # if the paths are the same just add the new one

            path:str = modified_file.new_path
        else: # if the paths are different, add the old path because other commits will have used the old path
            path:str = modified_file.old_path

        ## Add modified file paths by fixed commit to the set
        modified_file_paths_from_fix.add(path)


    # Looping through files that have been altered and identifying the commits that contributed to the alterations
    # Given a file path, get_commits_modified_file() returns all the commits that modified this file 
    for file_path in modified_file_paths_from_fix:
        commits_that_modified_file:list[str] = ffmpeg_git_repo.get_commits_modified_file(file_path)   

        for commit in commits_that_modified_file:

    
        timeline_of_commits:dict = ffmpeg_git_repo.get_commits_last_modified_lines(fixed_commit,bool=True)


def traverse_commit() -> None:
    global MODIFIED_FILES


    return None


def save_solution(hash_or_origin=ORIGIN_COMMIT_HASH):
    """_summary_

    Args:
        hash_or_origin (_type_, optional): _description_. Defaults to ORIGIN_COMMIT_HASH.

    Returns:
        _type_: _description_
    """
    return None



if __name__ == "__main__":
    None