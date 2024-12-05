import os
import psycopg2
from tqdm import tqdm
from pathlib import Path
from queries import execute_sql_file, table_exists
from config import pg_connect

# Input files/folders
select_cve_no_cwe_query = os.path.join(os.path.dirname(__file__), 'queries/select_cve_no_cwe.sql')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/cve_no_cwe.txt')

# Connection details
conn = pg_connect()

def main():
	cursor = conn.cursor()
	if not table_exists(cursor, "cve_patches"):
		raise Exception("Table cve_patches does not exist. Please run create_db_tables.py first.")

	execute_sql_file(cursor, Path(select_cve_no_cwe_query))
	results = cursor.fetchall()

	with open(output_file, 'w') as f:
		for row in results:
			f.write(f"{row[0]}\n")

	print(f"Found {len(results)} CVEs without CWEs. Results written to {output_file}")

	cursor.close()
	conn.close()

if __name__ == "__main__":
	main()
