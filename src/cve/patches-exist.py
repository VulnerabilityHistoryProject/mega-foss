import json
import os
import orjson

patches_json_file = os.path.join(os.path.dirname(__file__),  '../../lists/nvdcve-github-patches.json')

data = []

with open(patches_json_file, 'r') as f:
	json_str = f.read()
	data = orjson.loads(json_str)

for item in data:
	print(item['cve_id'], "\t",item["patches"])
