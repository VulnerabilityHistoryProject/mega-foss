# Assume this repo:
# is at ../cvelist

import pathlib
import os
import orjson

reposlist = os.path.join(os.path.dirname(__file__), '../../lists/c_repos_to_nvd.csv')
c_repos_to_nvd = open(reposlist, 'r')
vendor_product_list = {}
for line in c_repos_to_nvd:
	field = line.split(',')
	vendor_product_list[field[1]] = field[2].strip()

print(vendor_product_list.keys())
print(vendor_product_list.values())

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
					if vendor_name in vendor_product_list.keys():
						product_data = vendor['product']['product_data']
						for product in product_data:
							product_name = product['product_name']
							if product_name == vendor_product_list[vendor_name]:
								print(','.join([id, vendor_name, product_name]))
					else:
						pass
			else:
				pass
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
			data = orjson.loads(cve_file.read())
			id = data['cveMetadata']['cveId']
			state = data['cveMetadata']['state']
			if state != 'REJECT' and state != 'RESERVED':
				vendor_data = data['cveMetadata']['assignerOrgId']
				vendor_name = data['cveMetadata']['assignerShortName']
				if vendor_name in vendor_product_list.keys():
					print(','.join([id, vendor_name]))
					# print('\n')
		except UnicodeDecodeError as e:
			print(e.reason)
			print(f"ERROR loading {p}")
		except KeyError as k:
			print(str(k) +  " not found in " + cve_file.name)
