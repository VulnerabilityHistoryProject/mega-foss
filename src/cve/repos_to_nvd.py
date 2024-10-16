"""
Given a list of repositories, this script will attempt to match them with the Vendor and Product names from CVE JSONs.
"""

import os
import psycopg2
from tqdm import tqdm
from enum import Enum
from pathlib import Path

# Input files/folders
repolist = os.path.join(os.path.dirname(__file__), 'repos.txt')
filter_cve_data = os.path.join(os.path.dirname(__file__), 'queries/select_cve_vendor_product.sql')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/repos_to_nvd.csv')
missing_file = os.path.join(os.path.dirname(__file__), 'output/repos_to_nvd_missing.txt')
fix_file = os.path.join(os.path.dirname(__file__), 'output/repos_to_nvd_manual_fix.txt')

# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password=PASSWORD,# <--- Change this to your password
    host="localhost"
)

class RepoState(Enum):
	NO_MATCHES = 0
	MULTIPLE_MATCHES = 1
	FOUND_MATCH = 2

class Repo:
	def __init__(self, name=None, vendor=None, url=None):
		self.ids = (str(vendor).lower(), str(name).lower())
		self.url = url
		self.matches = list()
		self.state: RepoState = RepoState.NO_MATCHES
		self.cve_vendor = None
		self.cve_product = None

	def add_match(self, row):
		cve_id, _, _, vendor, product, urls = row
		self.matches.append((vendor, product))

	def resolve(self):
		matches_set = set([(a.lower(), b.lower()) for a,b in filter(lambda match: match[0] != 'n/a', self.matches)])
		len_matches = len(matches_set)

		if len_matches == 0:
			self.state = RepoState.NO_MATCHES
		elif len_matches > 1:
			if self.ids in matches_set:
				self.state = RepoState.FOUND_MATCH
				self.cve_vendor, self.cve_product = self.ids
			else:
				self.state = RepoState.MULTIPLE_MATCHES
		else:
			self.state = RepoState.FOUND_MATCH
			self.cve_vendor, self.cve_product = self.matches[0]

	def __str__(self):
		out = f"[ {self.url} ]\n"
		if self.cve_vendor is not None and self.cve_product is not None:
			out += f"Vendor: {self.cve_vendor}\nProduct: {self.cve_product}\n"
		else:
			vendors = [vendor for vendor, _ in self.matches]
			products = [product for _, product in self.matches]
			out += f"Vendor: {list(vendors)}\nProduct: {list(products)}\n"

		return out + "-"*80

	def __repr__(self):
		return self.__str__()

def read_data() -> list[Repo]:
	"""
	Reads the list of repos from the file into a list of Repo objects
	"""
	repos: list[Repo] = list()

	with open(repolist, 'r') as f:
		for repo in f:
			repo = repo.strip()
			vendor, name = repo.strip().split('/')
			repos.append(Repo(name, vendor, repo))

	return repos


def find_repo_matches(repos: list[Repo], cursor: psycopg2.extensions.cursor):
	"""
	Finds vendor, product matches for each repo in the list of repos
	"""
	with open(Path(filter_cve_data), 'r') as f:
		filter_cve_vendor_product = f.read()
		for repo in tqdm(repos, desc="Finding Repo Matches"):
			test_vendor, test_product = repo.ids
			url = repo.url
			cursor.execute(filter_cve_vendor_product, (f'%{test_vendor}%', f'%{url}%', f'{test_product}', f'{url}'))
			rows = cursor.fetchall()
			for row in rows:
				repo.add_match(row)

def generate_outputs(repos: list[Repo]) -> tuple[str, str, str]:
	output_missing = ""
	output_fix = ""
	output = "github repo,cve vendor,cve product\n"

	for repo in tqdm(repos, desc="Writing outputs"):
		repo.resolve()
		match repo.state:
			case RepoState.NO_MATCHES:
				output_missing += f"{repo.url}\n"
			case RepoState.MULTIPLE_MATCHES:
				output_fix += f"{repo}\n"
			case RepoState.FOUND_MATCH:
				output += f"{repo.url},{repo.cve_vendor},{repo.cve_product}\n"

	return output, output_missing, output_fix

def write_output(output, output_missing, output_fix):
	with open(output_file, 'w') as f:
		f.write(output)

	with open(missing_file, 'w') as f:
		f.write(output_missing)

	with open(fix_file, 'w') as f:
		f.write(output_fix)

def main():
	cursor = conn.cursor()
	repos = read_data()
	find_repo_matches(repos, cursor)
	output, output_missing, output_fix = generate_outputs(repos)
	write_output(output, output_missing, output_fix)
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
