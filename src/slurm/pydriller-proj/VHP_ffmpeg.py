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
from typing import Counter

from pydriller import Git,ModifiedFile

FIXED_VULN_COMMIT_HASH:str = "54e488b9da4abbceaf405d6492515697" # The hash of the commit that fixed CVE-2015-8218
ORIGIN_COMMIT_HASH:str = ""
FFMPEG_PATH_TO_REPO:str = ""
MODIFIED_FILES:set[str] = set()



def git_blame(file_path:str,line_start:int,line_end:int) -> str:
    """

    Keep it simple and only process one file at a time for now.

    Args:
        file_path (str): path to the file where the vulnerability was introduced & fixed
        line_start (int): start line of where the change for the vulnerability was introduced
        line_end (int): end line of where the change for the vulnerability was introduced

    Returns:
        str: result from the git blame <file_path>
    """

    result = subprocess.run(
        ['git','blame',file_path, '-L',f'{line_start},{line_end}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    return result.stdout.decode()


def extract_most_common_commit_and_author(blame_output: str) -> dict[str,str]:
    """Extract the most common commit hash and the author with the highest contribution.

    Args:
        blame_output (str): Output from `git blame` command.

    Returns:
        dict: Dictionary with the most common commit hash and the author with the most contributions.
    """
    commit_hashes:list[str] = []
    authors:list[str] = []

    lines:list[str] = blame_output.splitlines()

    for line in lines:
        # Validate and parse each line
        if not line.strip():
            continue  # Skip empty lines

        parts = line.split(maxsplit=3)
        if len(parts) < 2:
            continue  # Skip malformed lines

        commit_hash:str = parts[0]
        author:str = parts[1].strip('()')  # Remove parentheses if present

        # Collect commit hash and author
        commit_hashes.append(commit_hash)
        authors.append(author)

    # Find the most common commit hash
    commit_counter: Counter[str] = Counter(commit_hashes)
    most_common_commit: str = commit_counter.most_common(1)[0][0] if commit_counter else None

    # Find the author with the highest number of contributions
    author_counter: Counter[str] = Counter(authors)
    most_common_author: str = author_counter.most_common(1)[0][0] if author_counter else None

    return {
        "most_common_commit_hash": most_common_commit,
        "most_common_author": most_common_author,
    }



def git_show_vuln_changes(original_commit_hash:str,file_path:str,original_hash_start:int,original_hash_end:int) -> str:
    """_summary_

    Args:
        original_commit_hash (str): _description_
        file_path (str): _description_

    Returns:
        str: implementation of vulnerability
    """


    result = subprocess.run(
        ['git','show',original_commit_hash,':',file_path,'|','sed','-n','f{},{}p'.format(original_hash_start,original_hash_end)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )


    return result.stdout.decode()


def get_lines_changed_in_fix(modified_file:ModifiedFile)-> tuple[int,int]:
    """_summary_

    Args:
        modified_file (ModifiedFile): _description_

    Returns:
        tuple[int,int]: _description_
    """

    added_lines:list[tuple[int,str]] = modified_file.diff_parsed['added']
    deleted_lines:list[tuple[int,str]] = modified_file.diff_parsed['deleted']

    # Get the earlies added line number
    earliest_added_line:int = added_lines[0][0]

    # Get the earliest deleted line number
    earliest_deleted_line: int = deleted_lines[0][0]

    # Get the last added line number
    if added_lines:
        last_added_line:str = added_lines[-1][1] # end_line of last added tuple
    else:
        last_added_line = None

    # Get the last deleted line number
    if deleted_lines:
        last_deleted_line:str = deleted_lines[-1][1] # end_line of last deleted tuple
    else:
        last_deleted_line = None
    
    ### Next steps
    # 1. git blame line above the 'earliest added line' and below 'last_added_line' --> get the hash associated with that commit
    # 2. use the parent commit (commit that introd the vuln) for the git_show <parent hash>:<path_to_file> | sed -n '5,7p'
    # add some error handling and confirmation for how many modified files there are
    # figure out how to write the solution to a file in the RC program
    # test code on the ffmped repo locally to make sure that it works

   


    return (int(earliest_added_line),int(last_added_line))


def find_modified_files(commit_hash:str = FIXED_VULN_COMMIT_HASH, repo_path:str = FFMPEG_PATH_TO_REPO) -> set[str]:
    """_summary_

    Args:
        commit_hash (str, optional): The hash of the bug fix as seen here --> https://vulnerabilityhistory.org/commits/d4a731b84a08f0f3839eaaaf82e97d8d9c67da46 -->  Defaults to FIXED_VULN_COMMIT_HASH.


        repo_path (str, optional): the path to the ffmpeg repo on RC -->  Defaults to FFMPEG_PATH_TO_REPO.
    """
    
    # Create empty set for files that were modified by the fixed commit
    modified_file_paths_from_fix:set[str] = set()

    # converting path to a Git object --> ffmpeg git repo
    ffmpeg_git_repo= Git(repo_path)

    # Getting the commit object from the fixed commit hash the fixed the vulnerability
    fixed_commit = ffmpeg_git_repo.get_commit(commit_hash)

    

    # Add modified files to the set for later reference
    for modified_file in fixed_commit.modified_files:

        path:str = ""

        if modified_file.old_path == modified_file.new_path: # if the paths are the same just add the new one

            path = modified_file.new_path
        else: # if the paths are different, add the old path because other commits will have used the old path
            path = modified_file.old_path

        ## Add modified file paths by fixed commit to the set
        modified_file_paths_from_fix.add(path)

        #modified_file.diff_parsed


    return modified_file_paths_from_fix

    
def traverse_commit(modified_files: set[str], repo_path: str = FFMPEG_PATH_TO_REPO) -> None:
    """
    Traverse commits to find those that modified the given files.

    Args:
        modified_files (set[str]): Set of file paths to analyze.
        repo_path (str): Path to the ffmpeg repository in RC cluster.
    """
    ### Decided to go a different route with finding the original commit, but I will keep this code for reference for later

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


def save_solution(hash_or_origin:str =ORIGIN_COMMIT_HASH) -> None:
    """_summary_

    Args:
        hash_or_origin (_type_, optional): _description_. Defaults to ORIGIN_COMMIT_HASH.

    Returns:
        _type_: _description_
    """

    
    return None      



if __name__ == "__main__":
    # Find modified files in the fixed commit
    modified_files_by_fixed_commit:set[str] = find_modified_files(commit_hash=FIXED_VULN_COMMIT_HASH)

    # Extract the lines that were changed in each modified file
    ### In the case of CVE-2015-8218 I happen to know that only 1 file was changed. For sake of simplicity, I won't write hypter-robust code
    ### capable of handling multiple modified files (edge cases)
    for file in modified_files_by_fixed_commit:
        lines_changed:tuple[int,int] = get_lines_changed_in_fix(file)


    # Blame the line 1 above start 
    # Blame the line 1 below end
    # This will hopefully get me the original author and commit of the vulnerability
    start:int = lines_changed[0]
    end:int = lines_changed[1]
    blame_ouput: str = git_blame(file_path=FFMPEG_PATH_TO_REPO,line_start=start,line_end=end)

    # Extract the most common commit hash and author of those commits
    original_commit_dict: dict[str, str]= extract_most_common_commit_and_author(blame_output=blame_ouput)

    ORIGIN_COMMIT_HASH = original_commit_dict['most_common_commit_hash']


    modified_files_by_vuln_commit:set[str] = find_modified_files(commit_hash=ORIGIN_COMMIT_HASH)


    for file1,file2 in zip(modified_files_by_fixed_commit,modified_files_by_vuln_commit):
       assert(file1 == file2)

    
