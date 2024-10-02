
"""
Given a list of repositories, this script will attempt to match them with the Vendor and Product names from CVE JSONs.
"""

# SQL Queries
QUERY_CVE_TABLE="""
	CREATE TABLE cve_json_data (
	    id SERIAL PRIMARY KEY,
	    data JSONB
	);
"""

QUERY_GET_CVE_IDS="""
	SELECT jt.*
	FROM cve_json_data,
	LATERAL JSON_TABLE(
	    data,
	    '$[*]'
	    COLUMNS(
	        cve_id TEXT PATH '$.cveMetadata.cveId',
	    )
	) AS jt;
"""

# Assume this repo:
# is at ../cvelist
import pathlib
import os
import re
import orjson
import psycopg2
from tqdm import tqdm

# Input files/folders
cvelist = os.path.join(os.path.dirname(__file__), '../cves')

# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password="1599",
    host="localhost"
)

URL_REGEX = re.compile(r"https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)")


def load_jsons(cursor):
	cvelist_path = pathlib.Path(cvelist)
	for p in tqdm(list(cvelist_path.rglob("CVE*.json")), desc="Loading JSONs"):
		with open(p, 'r') as f:
			try:
				data_str = f.read()
				data = orjson.loads(data_str)
				cursor.execute("INSERT INTO cve_json_data (data) VALUES (%s)", [orjson.dumps(data).decode()])
			except UnicodeDecodeError as e:
				print(e.reason)
				print(f"ERROR loading {p}")
			except Exception as e:
				print(e)
				print(f"ERROR loading {p}")

def main():
	cursor = conn.cursor()
	load_jsons(cursor)
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
