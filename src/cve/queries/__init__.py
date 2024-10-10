from psycopg2.extensions import cursor as Cursor
from pathlib import Path

def execute_sql_file(cursor: Cursor, file_path: Path, *params):
	"""
	Execute an SQL file
	:param cursor: psycopg2 cursor object
	:param file_path: str
	:param params: tuple
	:return: None
	"""
	with open(file_path, 'r') as file:
		try:
			sql = file.read()
			if params:
				cursor.execute(sql, tuple(params))
			else:
				cursor.execute(sql)
		except Exception as e:
			raise Exception(f"Error executing {file_path}: {e}")



def table_exists(cursor: Cursor, table_name: str) -> bool:
	"""
	Check if a table exists in the current database
	:param cursor: psycopg2 cursor object
	:param table_name: str
	:return: bool
	"""
	cursor.execute(f"""
	    SELECT EXISTS (
	        SELECT FROM information_schema.tables
	        WHERE table_name = '{table_name}'
	    )
	""")

	result = cursor.fetchone()

	return bool(result) and bool(result[0])
