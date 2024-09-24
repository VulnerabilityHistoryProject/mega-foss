# Assume this repo:
# is at ../cvelist

import pathlib
import os
# import json
import orjson
import re


cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
list_txt = '../../lists/c_repos.txt'

CVE_REGEX = re.compile("CVE\-\d{4}\-\d+")
COMMIT_REGEX = re.compile("commit/([\da-f]{40})")

print(f"Reading CVE repo from {cvelist}")

repos = []

with open(os.path.join(os.path.dirname(__file__), list_txt), mode="r") as repos_txt:
	repos = repos_txt.read().splitlines()

def check_useful_patch(url, json_path):
	for repo in repos:
		if f"github.com/{repo}" in url:
			global CVE_REGEX
			cve_match = CVE_REGEX.search(json_path)
			cve = "(NO CVE in JSON??)"
			if cve_match:
				cve = cve_match.group(0)
			commit = ""
			commit_match = COMMIT_REGEX.search(url)
			if commit_match:
				commit = commit_match.group(1)
			print(f"{repo}\t{cve}\t{commit}")


cvelist_path = pathlib.Path(cvelist)
for p in cvelist_path.rglob("CVE*.json"):
	with open(p, 'r') as f:
		try:
			data = orjson.loads(f.read())
			if 'references' in data:
				for ref in data['references'].get("reference_data", []):
					check_useful_patch(ref.get("url",""), str(p))

			# print(data['CVE_data_meta']['ID'])
			# print('.', end="")
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
		except KeyError:
			breakpoint()

print('Done!')