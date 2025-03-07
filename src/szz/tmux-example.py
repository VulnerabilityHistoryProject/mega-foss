
from pydriller.repository import Repository

for commit in pydriller.Repository('path/to/the/repo').traverse_commits():
    print('Hash {}, author {}'.format(commit.hash, commit.author.name))
