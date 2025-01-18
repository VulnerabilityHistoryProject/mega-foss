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
import subprocess
import datetime

from pydriller import Git
from pydriller import ModifiedFile
from pydriller import Commit

FIXED_VULN_COMMIT_HASH:str = "54e488b9da4abbceaf405d6492515697"
ORIGIN_COMMIT_HASH:str = ""
FFMPEG_PATH_TO_REPO:str = ""
MODIFIED_FILES:set[str] = set()



def git_blame(file_path:str,line_start:int,line_end:int):
    """

    Keep it simple and only process one file at a time for now.

    Args:
        file_path (str): path to the file where the vulnerability was introduced
        line_start (int): start line of where the change for the vulnerability was introduced
        line_end (int): end line of where the change for the vulnerability 

    Returns:
        _type_: _description_
    """

    result = subprocess.run(
        ['git','blame',file_path, '-L',f'{line_start},{line_end}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    return result.stdout.decode()


def extract_blame_info(blame_output:str) -> None:
    global ORIGIN_COMMIT_HASH
    lines:list[str] = blame_output.splitlines()

    for line in lines:
        parts = line.split(' ',2)
        commit_hash:str = parts[0]
        author:str = parts[1][1:1] ## not currently using this author field but maybe in the future
        ORIGIN_COMMIT_HASH = commit_hash


def get_lines_changed_in_fix(modified_file:ModifiedFile)-> tuple[int,int]:

    added_lines:list[tuple[int,str]] = modified_file.diff_parsed['added']
    deleted_lines:list[tuple[int,str]] = modified_file.diff_parsed['deleted']

    # Get the earlies added line number
    earliest_added_line:int = added_lines[0][0]

    # Get the earliest deleted line number
    earliest_deleted_line: int = deleted_lines[0][0]

    # Get the last added line number
    if added_lines:
        last_added_line:int = added_lines[-1][1] # end_line of last added tuple
    else:
        last_added_line: None = None

    # Get the last deleted line number
    if deleted_lines:
        last_deleted_line:int = deleted_lines[-1][1] # end_line of last deleted tuple
    else:
        last_deleted_line: None = None
    
    # Next steps
    # 1. git blame line above the 'earliest added line' and below 'last_added_line'
    # 1.a check to see if the commit is the same , if yes this means it's probably the bug
    # 2. use the parent commit (commit that introd the vuln) for the git_show <parent hash>:<path_to_file> | sed -n '5,7p'
    # add some error handling and confirmation for how many modified files there are
    # figure out how to write the solution to a file in the RC program


    return None
def find_modified_files(fixed_commit_hash:str = FIXED_VULN_COMMIT_HASH, repo_path:str = FFMPEG_PATH_TO_REPO) -> set[str]:
    """_summary_

    Args:
        fixed_commit_hash (str, optional): The hash of the bug fix as seen here --> https://vulnerabilityhistory.org/commits/d4a731b84a08f0f3839eaaaf82e97d8d9c67da46 -->  Defaults to FIXED_VULN_COMMIT_HASH.


        repo_path (str, optional): the path to the ffmpeg repo on RC -->  Defaults to FFMPEG_PATH_TO_REPO.
    """
    
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

        modified_file.diff_parsed


    return modified_file_paths_from_fix

    
def traverse_commit(modified_files: set[str], repo_path: str = FFMPEG_PATH_TO_REPO) -> None:
    """
    Traverse commits to find those that modified the given files.

    Args:
        modified_files (set[str]): Set of file paths to analyze.
        repo_path (str): Path to the ffmpeg repository in RC cluster.
    """

    ffmpeg_git_repo:Git = Git(repo_path)

    # Looping through files that have been altered and identifying the commits that contributed to the alterations

    # Given a file path, get_commits_modified_file() returns all the commits that modified this file 
    for file in modified_files:

        commits_that_modified_file:list[str] = ffmpeg_git_repo.get_commits_modified_file(file)   

        for commit in commits_that_modified_file:

            ffmpeg_git_repo.get_commits_modified_file
           

    """
    

    """

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
    # Find modified files in the fixed commit
    modified_files_by_fixed_commit:set[str] = find_modified_files()

    # Analyze commits that modified these files
    traverse_commit(modified_files_by_fixed_commit)