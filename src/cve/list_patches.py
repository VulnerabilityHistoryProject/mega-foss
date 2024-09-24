# Assume this repo:
# is at ../cvelist

import pathlib
import os
import json
# import orjson


cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
print(f"Reading CVE repo from {cvelist}")

cvelist_path = pathlib.Path(cvelist)
for p in cvelist_path.rglob("CVE*.json"):
	with open(p, 'r') as f:
		try:
			data = json.loads(f.read())
			if 'references' in data:
				for ref in data['references'].get("reference_data", []):
					if 'github' in ref.get("url", ""):
						print('g', end="")

			# print(data['CVE_data_meta']['ID'])
			print('.', end="")
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
		except KeyError:
			breakpoint()

print('Done!')