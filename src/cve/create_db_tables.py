"""
This script will create create cve data tables on local postgres database
"""

import os
import re
import orjson
import psycopg2
from tqdm import tqdm
from pathlib import Path
from cve.queries import execute_sql_file as sql, table_exists

# Input files/folders
# cvelist = os.path.join(os.path.dirname(__file__), '../cves')
cvelist = os.path.join(os.path.dirname(__file__), '../../../../Misc/cvelistV5/cves/')

create_json = os.path.join(os.path.dirname(__file__), '/queries/create_cve_json.sql')
insert_json = os.path.join(os.path.dirname(__file__), '/queries/insert_cve_json.sql')
create_cve_data = os.path.join(os.path.dirname(__file__), '/queries/create_cve_data.sql')
insert_cve_data = os.path.join(os.path.dirname(__file__), '/queries/insert_cve_data.sql')

# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password=PASSWORD, # <--- Enter your password here
    host="localhost"
)

def load_jsons(cursor):
	"""
	Load all JSONs from cvelist folder into the database
	"""
	cvelist_path = Path(cvelist)
	insert_json_path = Path(insert_json)
	with open(insert_json_path, 'r') as file:
		insert_cve_json = file.read()
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

def main():
	cursor = conn.cursor()
	if not table_exists(cursor, 'cve_json_data'):
		print("Creating cve_json_data table")
		sql(cursor, Path(create_json))
		load_jsons(cursor)
	if not table_exists(cursor, 'cve_data'):
		print("Creating cve_data table")
		sql(cursor, Path(create_cve_data))
		sql(cursor, Path(insert_cve_data))
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
