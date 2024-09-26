# Assume this repo:
# is at ../cvelist

import pathlib
import os
import orjson

cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
print(f"Reading CVE repo from {cvelist}")

cve_ids = pathlib.Path('/cve_ids.csv')
# cve_id_output = open(cve_ids, 'x')

cvelist_path = pathlib.Path(cvelist)
for p in cvelist_path.rglob("CVE*.json"):
	with open(p, 'r') as cve_file:
		try:
			data = orjson.loads(cve_file.read())
			id = data['CVE_data_meta']['ID']
			state = data['CVE_data_meta']['STATE']
			if state != 'REJECT':
				vendor_data = data['affects']['vendor']['vendor_data']
				for vendor in vendor_data:
					vendor_name = vendor['vendor_name']
					product_data = vendor['product']['product_data']
					for product in product_data:
						product_name = product['product_name']
						print(','.join([id, vendor_name, product_name]))
						# TODO: sort by vendor and product

			print('.', end="")
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")