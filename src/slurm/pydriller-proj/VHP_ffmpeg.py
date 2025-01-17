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
### TASK --> figure out where this script will be run and the path to ffmpeg. I want local repo not the git web link.


def find_origin_commit(fixed_commit_hash:str = FIXED_VULN_COMMIT_HASH, repo_path:str = FFMPEG_PATH_TO_REPO):

    # Create empty set for files that were modified by the fixed commit
    modified_files_from_fix:set = set()

    # converting path to a Git object --> ffmpeg git repo
    ffmpeg_gr= Git(repo_path)

    # Getting the commit object from the fixed commit hash the fixed the vulnerability
    fixed_commit = ffmpeg_gr.get_commit(fixed_commit_hash)


    # Add modified files to the set for later reference
    for modified_file in fixed_commit.modified_files:
        modified_files_from_fix.add(modified_file)

        

    timeline_of_commits:dict = ffmpeg_gr.get_commits_modified_file(fixed_commit)





if __name__ == "__main__":
    None