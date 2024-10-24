import os
from pathlib import Path

# Input files/folders
c_repos_to_nvd_csv = os.path.join(os.path.dirname(__file__), "../../../lists/c_repos_to_nvd.csv")
unfixed_missing = os.path.join(os.path.dirname(__file__), "repos_to_nvd_missing.txt")

# Output files
fixed_missing = os.path.join(os.path.dirname(__file__), "repos_to_nvd_missing_fixed.txt")

def main():
	output = ""
	with open(Path(c_repos_to_nvd_csv), 'r') as f:
		with open(Path(unfixed_missing), 'r') as g:
			nvd = f.read()
			for line in g:
				if line.strip() not in nvd:
					output += line

	with open(Path(fixed_missing), 'w') as h:
		h.write(output)

if __name__ == "__main__":
	main()
