"""
Given a list of repositories, this script will attempt to match them with the Vendor and Product names from CVE JSONs.
"""

# Assume this repo:
# is at ../cvelist
import pathlib
import os
import re
import orjson
import psycopg2
from tqdm import tqdm

# Input files/folders
cvelist = os.path.join(os.path.dirname(__file__), '../cves')
repolist = os.path.join(os.path.dirname(__file__), 'repos.txt')
id_to_name = os.path.join(os.path.dirname(__file__), 'cve-id-to-name.json')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/repos_to_nvd.csv')
missing_file = os.path.join(os.path.dirname(__file__), 'output/missing_repos.txt')
fix_file = os.path.join(os.path.dirname(__file__), 'output/manual_fix_repos.txt')

# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password=PASSWORD,# <--- Change this to your password
    host="localhost"
)

# QUERIES
FILTER_CVE_DATA = """
SELECT * FROM cve_data
WHERE (vendor ILIKE %s OR urls::TEXT ILIKE %s)
   AND (product ILIKE %s OR product ILIKE %s);
"""

class Repo:
	ids: tuple
	def __init__(self, name=None, vendor=None, url=None):
		self.ids = (str(vendor).lower(), str(name).lower())
		self.url = url
		self.matches = list()
		self.state = 0
		self.cve_vendor = None
		self.cve_product = None

	def add_match(self, row):
		cve_id, vendor, product, urls = row
		self.matches.append((vendor, product))

	def resolve(self):
		matches_set = set([(a.lower(), b.lower()) for a,b in filter(lambda match: match[0] != 'n/a', self.matches)])
		len_matches = len(matches_set)

		if len_matches == 0:
			self.state = 0
		elif len_matches > 1:
			if self.ids in matches_set:
				self.state = 2
				self.cve_vendor, self.cve_product = self.ids
			else:
				self.state = 1
		else:
			self.state = 2
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

def read_data():
	id_map = dict()
	repos: list[Repo] = list()
	with open(repolist, 'r') as f:
		for repo in f:
			repo = repo.strip()
			vendor, name = repo.strip().split('/')
			repos.append(Repo(name, vendor, repo))

	with open(id_to_name, 'r') as f:
		id_map = orjson.loads(f.read())

	return repos, id_map


def find_repo_matches(repos, cursor):
	for repo in tqdm(repos, desc="Finding Repo Matches"):
		test_vendor, test_product = repo.ids
		url = repo.url
		cursor.execute(FILTER_CVE_DATA, (f'%{test_vendor}%', f'%{url}%', f'{test_product}', f'{url}'))
		rows = cursor.fetchall()
		for row in rows:
			repo.add_match(row)

def generate_outputs(repos: list[Repo]):
	output_missing = ""
	output_fix = ""
	output = "github repo,cve vendor,cve product\n"

	for repo in tqdm(repos, desc="Writing outputs"):
		repo.resolve()
		match repo.state:
			case 0:
				output_missing += f"{repo.url}\n"
			case 1:
				output_fix += f"{repo}\n"
			case 2:
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
	repos, id_map = read_data()
	find_repo_matches(repos, cursor)
	output, output_missing, output_fix = generate_outputs(repos)
	write_output(output, output_missing, output_fix)
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
