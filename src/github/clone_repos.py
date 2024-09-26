import os

dest     = '/shared/rc/sfs/mega-foss-repos'
list_txt = '../../lists/c_repos.txt'

with open(os.path.join(os.path.dirname(__file__), list_txt), mode="r") as repos_txt:
	for line in repos_txt:
		repo = line.strip()
		print("------------------------------")
		print(f"--- Cloning {repo} to ---")
		print("------------------------------")
		os.system(f"git clone https://github.com/{repo}.git {dest}/{repo}")
