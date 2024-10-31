"""
This script will create create cve data tables on local postgres database
"""

import os
import re
import orjson
import psycopg2
from tqdm import tqdm
from pathlib import Path
from queries import execute_sql_file, table_exists
from config import pg_connect

# Config
RESTART_DB = True

# Input files/folders
cvelist = os.path.join(os.path.dirname(__file__), '../../../cves/cves')
# cvelist = os.path.join(os.path.dirname(__file__), '../../../../Misc/cvelistV5/cves/')

create_json = os.path.join(os.path.dirname(__file__), 'queries/create_cve_json.sql')
insert_json = os.path.join(os.path.dirname(__file__), 'queries/insert_cve_json.sql')
create_cve_data = os.path.join(os.path.dirname(__file__), 'queries/create_cve_data.sql')
insert_cve_data = os.path.join(os.path.dirname(__file__), 'queries/insert_cve_data.sql')
create_cve_patches = os.path.join(os.path.dirname(__file__), 'queries/create_cve_patches.sql')
insert_cve_patches = os.path.join(os.path.dirname(__file__), 'queries/insert_cve_patches.sql')
create_cve_cwe_project = os.path.join(os.path.dirname(__file__), 'queries/create_cve_cwe_project.sql')

# Connection details
conn = pg_connect()

def load_jsons(cursor):
	"""
	Load all JSONs from cvelist folder into the database
	"""
	cvelist_path = Path(cvelist)
	insert_json_path = Path(insert_json)
	with open(insert_json_path, 'r') as file:
		insert_cve_json = file.read()
		# breakpoint()
		for p in tqdm(list(cvelist_path.rglob("CVE*.json")), desc="Loading JSONs"):

			with open(p, 'r') as f:
				try:
					data_str = f.read()
					data = orjson.loads(data_str)
					cursor.execute(insert_cve_json, [orjson.dumps(data).decode()])
				except UnicodeDecodeError as e:
					print(e.reason)
					print(f"ERROR loading {p}")
				except Exception as e:
					print(e)
					print(f"ERROR loading {p}")

def drop_tables(cursor):
	tables = ['cve_json_data', 'cve_data', 'cve_patches', 'cve_cwe_project', 'cve_project_no_cwe', 'c_cve_cwe_project', 'c_cve_project_no_cwe']

	for table in tables:
		cursor.execute(f"DROP TABLE IF EXISTS {table}")

def main():
	cursor = conn.cursor()
	if RESTART_DB:
		print("Dropping tables")
		drop_tables(cursor)
		conn.commit()
	if not table_exists(cursor, 'cve_json_data'):
		print("Creating cve_json_data table")
		execute_sql_file(cursor, Path(create_json))
		load_jsons(cursor)
	if not table_exists(cursor, 'cve_data'):
		print("Creating cve_data table")
		execute_sql_file(cursor, Path(create_cve_data))
		execute_sql_file(cursor, Path(insert_cve_data))
	if not table_exists(cursor, 'cve_patches'):
		print("Creating cve_patches table")
		execute_sql_file(cursor, Path(create_cve_patches))
		execute_sql_file(cursor, Path(insert_cve_patches))
	if not table_exists(cursor, 'cve_cwe_project'):
		print("Creating cve_cwe_project table")
		execute_sql_file(cursor, Path(create_cve_cwe_project))
	print("Committing changes")
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
