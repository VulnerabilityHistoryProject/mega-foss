# Assume this repo:
# is at ../cvelist

import os
import orjson
from tqdm import tqdm
from pathlib import Path
import psycopg2
from queries import execute_sql_file as execute_sql_file
from config import pg_connect

# Files/Folders
repo_to_nvd = os.path.join(os.path.dirname(__file__), '../../lists/c_repos_to_nvd.csv')
cvelist = os.path.join(os.path.dirname(__file__), '../../../cvelist')
cvelist_v5 = os.path.join(os.path.dirname(__file__), '../../../cvelistV5/cves')
# cvelist_v5 = os.path.join(os.path.dirname(__file__), '../../../../Misc/cvelistV5/cves/')
filter_id_name = os.path.join(os.path.dirname(__file__), 'queries/select_cve_id_assigner_name.sql')

# Connection details
conn = pg_connect()

def load_vendor_product_dict() -> dict:
	repo_to_nvd_path = Path(repo_to_nvd)
	with open(repo_to_nvd_path, 'r') as f:
		vendor_product_dict = {}
		for line in f:
			field = line.split(',')
			vendor_product_dict[field[1]] = field[2].strip()
		return vendor_product_dict

def safe_get(dict, *keys, default=None):
	return (
		dict.get(keys[0], default) if len(keys) == 1
		else safe_get(dict.get(keys[0], {}), *keys[1:], default=default)
	)

def process_cvelist(vendor_product_dict: dict):
	cvelist_path = Path(cvelist)

	for p in tqdm(list(cvelist_path.rglob("CVE*.json")), desc=f"Reading CVE repo from {cvelist}"):
		with open(p, 'r') as cve_file:
			try:
				data = orjson.loads(cve_file.read())
				id = data['CVE_data_meta']['ID']
				state = data['CVE_data_meta']['STATE']
				if state != 'REJECT' and state != 'RESERVED':
					vendor_data = safe_get(data, 'affects', 'vendor', 'vendor_data', default=[])
					for vendor in vendor_data:
						vendor_name = vendor['vendor_name']
						if vendor_name in vendor_product_dict.keys():
							product_data = vendor['product']['product_data']
							for product in product_data:
								product_name = product['product_name']
								if product_name == vendor_product_dict[vendor_name]:
									print(','.join([id, vendor_name, product_name]))
						else:
							pass
				else:
					pass
			except UnicodeDecodeError as e:
				print(e.reason)
				print(f"ERROR loading {p}")
			except KeyError as e:
				print(f"Key not found in {cve_file.name}")

def process_cvelist_v5(vendor_product_dict: dict):
	cvelistV5_path = Path(cvelist_v5)
	for p in tqdm(list(cvelistV5_path.rglob("CVE*.json")), desc=f"Reading CVE repo from {cvelist_v5}"):
		with open(p, 'r') as cve_file:
			try:
				data = orjson.loads(cve_file.read())
				id = data['cveMetadata']['cveId']
				state = data['cveMetadata']['state']
				if state != 'REJECT' and state != 'RESERVED':
					vendor_data = data['cveMetadata']['assignerOrgId']
					vendor_name = data['cveMetadata']['assignerShortName']
					if vendor_name in vendor_product_dict.keys():
						print(','.join([id, vendor_name]))
						# print('\n')
			except UnicodeDecodeError as e:
				print(e.reason)
				print(f"ERROR loading {p}")
			except KeyError as k:
				print(str(k) +  " not found in " + cve_file.name)

def process_db_cvelist(vendor_product_dict: dict):
	with conn.cursor() as cursor:
		vendors = vendor_product_dict.keys()
		execute_sql_file(cursor, Path(filter_id_name), list(vendors))
		rows = cursor.fetchall()
		for row in rows:
			print(row)


def main():
	vendor_product_dict = load_vendor_product_dict()
	print(vendor_product_dict.keys())
	print(vendor_product_dict.values())
	# process_cvelist(vendor_product_dict)
	# process_cvelist_v5(vendor_product_dict)
	process_db_cvelist(vendor_product_dict)

if __name__ == '__main__':
	main()
