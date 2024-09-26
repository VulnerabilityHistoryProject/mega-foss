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
			if state != 'REJECT' and state != 'RESERVED':
				vendor_data = data['affects']['vendor']['vendor_data']
				for vendor in vendor_data:
					vendor_name = vendor['vendor_name']
					if vendor_name != 'n/a':
						product_data = vendor['product']['product_data']
						for product in product_data:
							product_name = product['product_name']
							print(','.join([id, vendor_name, product_name]))
							# TODO: sort by vendor and product
						# print('\n')
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
		except KeyError as e:
			print("Key not found in " + cve_file.name)

cvelistV5 = os.path.join(os.path.dirname(__file__), '../../../cvelistV5/cves')
print(f"Reading CVE repo from {cvelistV5}")

cvelistV5_path = pathlib.Path(cvelistV5)
for p in cvelistV5_path.rglob("CVE*.json"):
	with open(p, 'r') as cve_file:
		try:
			data = orjson.loads(cve_file.read())["x_legacyV4Record"]
			id = data['CVE_data_meta']['ID']
			state = data['CVE_data_meta']['STATE']
			if state != 'REJECT' and state != 'RESERVED':
				vendor_data = data['affects']['vendor']['vendor_data']
				for vendor in vendor_data:
					vendor_name = vendor['vendor_name']
					if vendor_name != 'n/a':
						product_data = vendor['product']['product_data']
						for product in product_data:
							product_name = product['product_name']
							print(','.join([id, vendor_name, product_name]))
							# TODO: sort by vendor and product
						# print('\n')
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
		except KeyError as e:
			print("Key not found in " + cve_file.name)
