"""
This script will create create cve data tables on local postgres database
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
    password=PASSWORD_HERE, # <--- Enter your password here
    host="localhost"
)

# QUERIES
CREATE_CVE_JSON_DATA_TABLE = """
CREATE TABLE IF NOT EXISTS cve_json_data (
    id SERIAL PRIMARY KEY,
    data JSONB
)
"""

INSERT_CVE_JSON_DATA = "INSERT INTO cve_json_data (data) VALUES (%s)"

CREATE_CVE_DATA_TABLE = """
CREATE TABLE IF NOT EXISTS cve_data (
    cve_id TEXT,
    vendor TEXT,
    product TEXT,
    urls TEXT[]
);
"""

INSERT_CVE_DATA = r"""
WITH url_data AS (
    SELECT cve_json_data.data,
           ARRAY(
               SELECT url_element::TEXT
               FROM jsonb_path_query_array(cve_json_data.data, '$.**.url') AS urls,
                    jsonb_array_elements_text(urls) AS url_element
               WHERE url_element::TEXT ~ '^https?://(www\.)?github.com.*/\w+/\w+.*$'
           ) AS urls
    FROM cve_json_data
)
INSERT INTO cve_data (cve_id, vendor, product, urls)
SELECT
    jt.cve_id,
    affected_entry.vendor AS vendor,
    affected_entry.product AS product,
    url_data.urls AS urls
FROM url_data,
LATERAL JSON_TABLE(
    url_data.data,
    '$[*]'
    COLUMNS(
        cve_id TEXT PATH '$.cveMetadata.cveId',
        type TEXT PATH '$.dataType',
        affected JSON PATH '$.containers.cna.affected',
        assigner_id TEXT PATH '$.cveMetadata.assignerOrgId'
    )
) AS jt,
LATERAL JSON_TABLE(
    jt.affected,
    '$[*]'
    COLUMNS (
        vendor TEXT PATH '$.vendor',
        product TEXT PATH '$.product'
    )
) AS affected_entry;
"""

URL_REGEX = re.compile(r"https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)")

def table_exists(cursor, table_name):
	cursor.execute(f"""
	    SELECT EXISTS (
	        SELECT FROM information_schema.tables
	        WHERE table_name = '{table_name}'
	    )
	""")

	res = cursor.fetchone()
	return res and bool(res[0])

def load_jsons(cursor):
	cvelist_path = pathlib.Path(cvelist)
	for p in tqdm(list(cvelist_path.rglob("CVE*.json")), desc="Loading JSONs"):
		with open(p, 'r') as f:
			try:
				data_str = f.read()
				data = orjson.loads(data_str)
				cursor.execute(INSERT_CVE_JSON_DATA, [orjson.dumps(data).decode()])
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
		cursor.execute(CREATE_CVE_JSON_DATA_TABLE)
		load_jsons(cursor)
	if not table_exists(cursor, 'cve_data'):
		print("Creating cve_data table")
		cursor.execute(CREATE_CVE_DATA_TABLE)
		cursor.execute(INSERT_CVE_DATA)
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
