# Assume this repo:
# is at ../cvelist

import pathlib
import os
# import json
import orjson
import re
import csv

cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
list_txt = '../../lists/c_repos.txt'


CVE_REGEX = re.compile(r"CVE\-\d{4}\-\d+")
COMMIT_REGEX = re.compile(r"commit/([\da-f]{40})")
CWE_REGEX = re.compile(r"CWE\-\d+")

unique_cwes = set()

# print(f"Reading CVE repo from {cvelist}")

repos = []

with open(os.path.join(os.path.dirname(__file__), list_txt), mode="r") as repos_txt:
	repos = repos_txt.read().splitlines()

def process_reference(data, json_str, url):
	for repo in repos:
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

cvelist_path = pathlib.Path(cvelist)
for p in cvelist_path.rglob("CVE*.json"):
	with open(p, 'r') as f:
		try:
			json_str = f.read()
			data = orjson.loads(json_str)
			if 'references' in data:
				for ref in data['references'].get("reference_data", []):
					process_reference(data, json_str, ref.get("url",""))
		except UnicodeDecodeError as e:
			pass
			#FIXME What's going on here? doesn't seem to impact us but I don't like silencing this error
			# print(e.reason)
			# print(f"ERROR loading {p}")
		except KeyError:
			breakpoint()

print('----- Done! -----')
print("Unique CWEs")
for cwe in unique_cwes:
	print(cwe)
