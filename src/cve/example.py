# Assume this repo:
# is at ../cvelist

import pathlib
import os
import orjson


cvelist = os.path.join(os.path.dirname(__file__), '../cves/cves')
print(f"Reading CVE repo from {cvelist}")

cvelist_path = pathlib.Path(cvelist)
for p in cvelist_path.rglob("CVE*.json"):
	with open(p, 'r') as f:
		try:
			data = orjson.loads(f.read())
			# print(data['CVE_data_meta']['ID'])
			print('.', end="")
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
