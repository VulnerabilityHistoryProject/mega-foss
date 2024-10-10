# Assume this repo:
# is at ../cvelist

import os
import re
import orjson
import psycopg2
from tqdm import tqdm
from pathlib import Path
from queries import execute_sql_file as sql

# Files/Folders
cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
cvelist_v5 = os.path.join(os.path.dirname(__file__), '../../../../Misc/cvelistV5/cves/')
list_txt = os.path.join(os.path.dirname(__file__),  '../../lists/c_repos.txt')
select_patches = os.path.join(os.path.dirname(__file__),  'queries/select_cve_patches.sql')
select_unique_cwes = os.path.join(os.path.dirname(__file__),  'queries/select_unique_cwes.sql')


# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password="1599", # <--- Enter your password here
    host="localhost"
)

def load_repos() -> list[str]:
	repos = []

	with open(list_txt, mode="r") as repos_txt:
		repos = repos_txt.read().splitlines()

	return repos

def process_db_cvelist(repos: list[str], cursor: psycopg2.extensions.cursor):
	with open(Path(select_patches), 'r') as f:
		try:
			sql = f.read()
			data = []
			unique_cwes = set()
			for repo in tqdm(repos, desc="Processing repos"):
				cursor.execute(sql, (f"%{repo}%",))
				for (cve, cwes, commits) in cursor.fetchall():
					if cwes:
						for cwe in cwes:
							unique_cwes.add(cwe)
						cwes = cwes[0]
					if commits:
						commits = commits[0]
					data.append(f"{repo}\t{cve}\t{cwes}\t{commits}")
			return data, unique_cwes
		except Exception as e:
			print(f"SQL Error: {e}")
	# conn.commit()

def get_unique_cwes(cursor: psycopg2.extensions.cursor) -> set[str]:
	unique_cwes = set()
	sql(cursor, Path(select_unique_cwes))
	for row in tqdm(cursor.fetchall(), desc="Getting unique CWES"):
		unique_cwes.add(row[0])
	return unique_cwes


# Old Code --------------------------------------------
CVE_REGEX = re.compile(r"CVE\-\d{4}\-\d+")
COMMIT_REGEX = re.compile(r"commit/([\da-f]{40})")
CWE_REGEX = re.compile(r"CWE\-\d+")

def process_reference(repos, unique_cwes, data, json_str, url):
	for repo in tqdm(list(repos), desc=f"Processing {url}"):
		if f"github.com/{repo}" in url:
			cve = data['CVE_data_meta']["ID"]

			commit = ""
			commit_match = COMMIT_REGEX.search(url)
			if commit_match:
				commit = commit_match.group(1)

			cwe = ""
			# I know this is jank - but their json schema is sooo annoying
			cwe_match = CWE_REGEX.search(json_str)
			if cwe_match:
				cwe = cwe_match.group(0)
				unique_cwes.add(cwe)

			print(f"{repo}\t{cve}\t{commit}\t{cwe}")

def process_cvelist(repos, cvelist_dir):
	unique_cwes = set()
	cvelist_path = Path(cvelist_dir)
	for p in tqdm(list(cvelist_path.rglob("CVE*.json")), desc=f"Reading CVE repo from {cvelist_v5}"):
		with open(p, 'r') as f:
			try:
				json_str = f.read()
				data = orjson.loads(json_str)
				if 'references' in data:
					for ref in data['references'].get("reference_data", []):
						process_reference(repos, unique_cwes, data, json_str, ref.get("url",""))
			except UnicodeDecodeError as e:
				pass
				#FIXME What's going on here? doesn't seem to impact us but I don't like silencing this error
				# print(e.reason)
				print(f"ERROR loading {p}")
			except KeyError:
				breakpoint()
	print('----- Done! -----')
	return unique_cwes
# -----------------------------------------------------

def display_list(data):
	for d in data:
		print(d)

def main():
	repos = load_repos()
	# unique_cwes = process_cvelist(repos, cvelist_v5)

	data, unique_cwes = process_db_cvelist(repos, conn.cursor())
	display_list(data)

	# unique_cwes = get_unique_cwes(conn.cursor())
	print("Unique CWEs")
	display_list(unique_cwes)


if __name__ == "__main__":
	main()
