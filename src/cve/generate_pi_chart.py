"""
Print these out to the console spacing them out with tabs,
and then we can just copy and paste into Google Sheets and rebuild the chart.
--------------------------------------------------------------------------------
- Number of CVEs:
		How many CVEs are in each category of our Rust->CWE classification.
		e.g. 300 Virtually Impossible, 100 Discouraged via Borrow Checker, etc.
- Number of projects:
		How many projects have at least one CVE for each Rust->CWE classification.
		e.g. 30 projects had at least one Virtually Impossible, etc.
- Prominent Projects:
	We should pick a few projects that are prominent and had a lot of CVEs.
	e.g. Linux kernel or libxml or somethihg. Report the breakdown of each category
"""

"""
RUST CWE CATEGORIES:
	- No Help, or Langs Won't Help
	- Opt-In Measures Only
	- Discouraged via Borrow Checker
	- Discouraged via Debug Mode
	- Virtually Impossible
"""

import os
import csv
import psycopg2
from enum import Enum
from pathlib import Path
from collections import Counter

from psycopg2.extensions import cursor as Cursor
from queries import execute_sql_file
from config import pg_connect
from tqdm import tqdm

"""
CONSTANTS / CONFIG
"""
PRINT_CVE_NO_CWE = True
OUTPUT_TO_FILE = False
PROMINANT_PROJECTS = {
	"Linux": {
		('n/a','Linux kernel 4.15.0-rc9'),
		('Linux','Linux Kernel'),
		('n/a','Linux Kernel before 4.13.6'),
		('n/a','Linux kernel through v4.14-rc5'),
		('n/a','Linux kernel before 4.12.3'),
		('n/a','Linux kernel through 4.14.8'),
		('n/a','Linux kernel before 4.13'),
		('n/a','Linux kernel through 4.13.3'),
		('Linux','Linux'),
		('n/a','Linux kernel versions up to and including 4.12'),
		('n/a','Linux kernel before 4.14-rc6'),
		('Linux','kernel'),
		('n/a','Linux kernel 4.11'),
		('The Linux Kernel Organization','linux'),
		('n/a','Linux kernel v4.0-rc1 through v4.15-rc5'),
		('n/a','Linux Kernel'),
		('Linux Kernel Organization',' Inc.,Linux Kernel'),
		('n/a','Linux kernel'),
		('n/a','Linux kernel through 4.12.4'),
		('n/a','Linux kernel through version 4.9-rc1'),
		('n/a','Linux'),
		('n/a','Linux kernel through 4.11.1'),
		('n/a','Linux kernel before 4.10.13'),
		('n/a','kernel'),
		('n/a','Linux kernel v4.13 and newer'),
		('n/a','Kernel'),
		('n/a','Linux kernel before 4.9'),
		('n/a','Linux kernel before 4.6.2'),
		('n/a','Linux kernel before 4.13.12'),
	}
}

"""
FILES
"""
# Input files/folders
c_repos_nvd_csv = os.path.join(os.path.dirname(__file__), '../../lists/c_repos_to_nvd.csv')
rust_cwe_csv = os.path.join(os.path.dirname(__file__), '../../lists/rust_to_cwe.csv')
found_cve_cwe_mapping = os.path.join(os.path.dirname(__file__), '../../lists/c_cve_found_cwe_map.csv')
cwe_variants_to_base_csv = os.path.join(os.path.dirname(__file__), '../../lists/cwe_child_map.csv')
select_unique_cwe_query = os.path.join(os.path.dirname(__file__), 'queries/select_unique_cwes.sql')
select_cve_no_cwe_query = os.path.join(os.path.dirname(__file__), 'queries/select_cve_no_cwe.sql')
select_most_common_cwe_query = os.path.join(os.path.dirname(__file__), 'queries/select_most_common_cwe.sql')
create_c_cve_cwe_project = os.path.join(os.path.dirname(__file__), 'queries/create_c_cve_cwe_project.sql')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/pi_chart_data.txt')
missing_cwe = os.path.join(os.path.dirname(__file__), 'output/pi_chart_missing.txt')
cve_no_cwe_out = os.path.join(os.path.dirname(__file__), 'output/cve_no_cwe.txt')

# Connection details
conn = pg_connect()

class RustCSVData:
	def __init__(self, cwe_id=None, name=None, classification=None, vote=None, clippy=None):
		self.id = cwe_id
		self.name = name
		self.type = classification
		self.vote = vote
		self.clippy = clippy
		self.cves = set()
		self.ref = False

	def is_base(self) -> bool:
		return self.type == "Base"

	def is_reference(self) -> bool:
		return self.ref

	def __str__(self):
		return f"{self.id}: {self.vote}"

class CWEData:
	def __init__(self):
		self.projects = set()
		self.cves = set()
		self.cwes = set()

"""
LOADING DATA
"""
def load_rust_csv() -> dict[str, RustCSVData]:
	rust_cwe_csv_path = Path(rust_cwe_csv)
	try:
		with open(rust_cwe_csv_path, 'r') as f:
			reader = csv.reader(f)
			next(reader)
			data =  {f"CWE-{r[0]}": RustCSVData(r[0], r[1], r[3], r[7], r[8]) for r in reader}
			return data
	except FileNotFoundError:
		print(f"Could not find file: {rust_cwe_csv_path}")
		exit()
	except Exception as e:
		print(f"Error loading file: {e}")
		exit()

def load_cwe_variants_map(cwe_data):
	cwe_variants_to_base_csv_path = Path(cwe_variants_to_base_csv)
	try:
		with open(cwe_variants_to_base_csv_path, 'r') as f:
			reader = csv.reader(f)
			next(reader)
			# Headers: CWE-ID,Name,Type,Related Weakness,Parent,Vote,Clippy Helps?
			# Want: CWE-ID, Type, Vote (If it exists)
			for r in reader:
				id, cwe_type, parent_vote = f"CWE-{r[0]}", r[2], r[5]
				if id in cwe_data and parent_vote:
					if cwe_type == 'Base':
						continue
					d = cwe_data[id]
					d.vote = parent_vote
					d.ref = True
	except Exception as e:
		print(f"Error loading file: {e}")
		exit()

def create_c_cwe_project_map(cursor):
	"""
	Creates a table that maps C projects to their CWEs.
	"""
	c_repo_csv_path = Path(c_repos_nvd_csv)
	c_projects = list()

	with open(c_repo_csv_path, 'r') as f:
		reader = csv.reader(f)
		next(reader)
		for r in reader:
			if r:
				c_projects.append(f"{r[1]}/{r[2]}")

	execute_sql_file(cursor, Path(create_c_cve_cwe_project), c_projects, c_projects)
	print("Created C Repos -> CWE -> Project Map")

def load_c_cve_found_cwe(cursor: psycopg2.extensions.cursor):
	cve_cwe_map_path = Path(found_cve_cwe_mapping)
	GET_PROJECT_FROM_CVE = """
	SELECT project FROM cve_project_no_cwe
	WHERE cve_id=%s
	"""
	try:
		with open(cve_cwe_map_path, 'r') as f:
			reader = csv.reader(f)
			next(reader)
			found = []
			for r in reader:
				cve_id, cwe_id, mapping = r
				cursor.execute(GET_PROJECT_FROM_CVE, (cve_id,))
				project = cursor.fetchone()
				project = "n/a/n/a" if project is None else project[0]
				found.append((cve_id, cwe_id, mapping, project))
			return found
	except FileNotFoundError:
		print(f"Could not find file: {cve_cwe_map_path}")
		exit()

"""
PI CHART DATA ANALYSIS
"""
def analyze_single_project(cursor, rust_cwes: dict[str, RustCSVData], vendor, product, found_missing_data, prev_category_data=None):
	project = f"{vendor}/{product}"
	category_count = Counter({
		"No Help, or Langs Won't Help": 0,
		"Opt-In Measures Only": 0,
		"Discouraged via Borrow Checker": 0,
		"Discouraged via Debug Mode": 0,
		"Virtually Impossible": 0,
	}) if prev_category_data is None else prev_category_data[0]
	unspecified = list() if prev_category_data is None else prev_category_data[1]

	for (cve_id, cwe_id, _, p) in found_missing_data:
		if project != p:
			continue
		if cwe_id in rust_cwes:
			data = rust_cwes[cwe_id]
			if data.is_base() or data.is_reference() or data.vote != '':
				category_count[str(rust_cwes[cwe_id].vote)] += 1
			else:
				unspecified.append(cwe_id)
		else:
			unspecified.append(cwe_id)

	select_cwe_query = """
	SELECT * FROM c_cve_cwe_project
	WHERE project=%s
	"""

	cursor.execute(select_cwe_query, (project,))

	for (cve_id, cwe_id, _) in cursor.fetchall():
		if cwe_id in rust_cwes:
			data = rust_cwes[cwe_id]
			if data.is_base() or data.is_reference() or data.vote != '':
				category_count[str(rust_cwes[cwe_id].vote)] += 1
			else:
				unspecified.append(cwe_id)
		else:
			unspecified.append(cwe_id)

	return category_count, unspecified

def analyze_data(cursor: Cursor, rust_cwes:dict[str, RustCSVData], found_missing_data: list[tuple[str, str, str, str]]):
	category_data = {
		"No Help, or Langs Won't Help": CWEData(),
		"Opt-In Measures Only": CWEData(),
		"Discouraged via Borrow Checker": CWEData(),
		"Discouraged via Debug Mode": CWEData(),
		"Virtually Impossible": CWEData(),
		"Not Categorized": CWEData(),
	}
	missing_cwe_data = dict()

	for (cve, cwe, mapping, project) in found_missing_data:
		if cwe in rust_cwes:
			data = rust_cwes[cwe]
			if data.is_base() or data.is_reference() or data.vote != "":
				data = category_data[str(data.vote)]
				data.cves.add(cve)
				data.cwes.add(cwe)
				data.projects.add(project)
			else:
				category_data["Not Categorized"].projects.add(project)
				category_data["Not Categorized"].cves.add(cve)
				category_data["Not Categorized"].cwes.add(cwe)

	cursor.execute("SELECT * FROM c_cve_cwe_project")
	for (cve_id, cwe_id, project) in cursor.fetchall():
		if cwe_id in rust_cwes:
			data = rust_cwes[cwe_id]
			if (data.is_base() or data.is_reference() or data.vote != "") and data.vote in category_data:
				data = category_data[str(data.vote)]
				data.projects.add(project)
				data.cves.add(cve_id)
				data.cwes.add(cwe_id)
			else:
				category_data["Not Categorized"].projects.add(project)
				category_data["Not Categorized"].cves.add(cve_id)
				category_data["Not Categorized"].cwes.add(cwe_id)
				if cwe_id not in missing_cwe_data:
					missing_cwe_data[cwe_id] = CWEData()
				data = missing_cwe_data[cwe_id]
				data.projects.add(project)
				data.cves.add(cve_id)
				data.cwes.add(cwe_id)

	return category_data, missing_cwe_data

def generate_outputs(cursor, category_data: dict[str, CWEData], missing_cwe_data, projects_data):
	output = ""
	unspecified = ""

	output += "Category\tProjects\tCVEs\n"
	for category, data in category_data.items():
		output += f"{category}\t{len(data.projects)}\t{len(data.cves)}\n"

	unspecified += "Not Categorized CWEs (#Projects, #Cves)\n"
	unspecified += "============\n"
	for cwe, data in missing_cwe_data.items():
		unspecified += f"{cwe}\t{len(data.projects)}\t{len(data.cves)}\n"

	for project, (category_data, missing) in projects_data.items():
		output += f"\n\n{project}\n"
		output += "=" * len(project) + "\n"
		output += "Category\tCount\n"
		for category, count in category_data.items():
			output += f"{category}\t{count}\n"
		unspecified += f"\n\n{project} Not Categorized:\n"
		unspecified += "=" * len(project) + "===========\n"
		for cwe in missing:
			unspecified += f"{cwe}\n"
		output += f"Not Categorized\t{len(missing)}\n"

	no_cwes = ""
	if PRINT_CVE_NO_CWE:
		res = print_cve_no_cwe(cursor)
		if OUTPUT_TO_FILE:
			no_cwes += res[0]
		else:
			no_cwes += f"Total CVE's without CWEs: {res[1]}\n"
		for project, vp_list in PROMINANT_PROJECTS.items():
			no_cwes += f"\n -- {project} -- \n"
			for vendor, product in vp_list:
				res = print_cve_no_cwe_single_project(cursor, vendor, product)
				if OUTPUT_TO_FILE:
					no_cwes += f"{vendor}/{product} ({res[1]}):\n {res[0]}"
				else:
					no_cwes += f"{vendor}/{product}: {res[1]} CVE's without CWEs\n"


	return output, unspecified, no_cwes

def output_data(out_str, missing_str, no_cwes):
	with open(Path(output_file), 'w') as f:
		f.write(out_str)

	with open(Path(missing_cwe), 'w') as f:
		f.write(missing_str)

	with open(Path(cve_no_cwe_out), 'w') as f:
		for cve in no_cwes:
			f.write(f"{cve}\n")

"""
MISC DATA ANALYSIS
"""
def print_cve_no_cwe(cursor):
	# execute_sql_file(cursor, Path(select_cve_no_cwe_query))
	select_cve_no_cwe = """
	SELECT * FROM c_cve_project_no_cwe
	"""

	cursor.execute(select_cve_no_cwe)
	results = cursor.fetchall()
	result_str = ""

	for row in results:
		result_str += f"{row[0]}\n"

	return result_str, len(results)

def print_cve_no_cwe_single_project(cursor, vendor:str, product:str):
	project = f"{vendor}/{product}"
	select_cve_no_cwe = """
	SELECT * FROM c_cve_project_no_cwe
	WHERE project=%s
	"""

	cursor.execute(select_cve_no_cwe, (project,))
	results = cursor.fetchall()

	result_str = "CVE's without CWEs\n"

	if not OUTPUT_TO_FILE:
		for row in results:
			result_str += f"{row[0]}\n"

	return result_str, len(results)

def print_unique_cwes(category_data: dict[str, CWEData]):
	cwes = set([cwe for data in category_data.values() for cwe in data.cwes])

	print("Unique CWEs")
	print("-" * 10)
	for cwe in cwes:
		print(cwe)

def print_most_common_cwes(cursor, found_missing, category_data, cwe_data, limit: int = 10):
	INSERT_FOUND_MISSING = """
	INSERT INTO c_cve_cwe_project (cve_id, cwe_id, project)
	VALUES %s
	"""
	# print(cwe_data)

	found_missing = [(cve, cwe, project) for (cve, cwe, mapping, project) in found_missing]
	from psycopg2.extras import execute_values
	execute_values(cursor, INSERT_FOUND_MISSING, found_missing)

	execute_sql_file(cursor, Path(select_most_common_cwe_query))
	cwes = cursor.fetchall()
	cwe_count = Counter({cwe: (cve_cnt, pj_cnt) for cwe, cve_cnt, pj_cnt in cwes})

	print(f"Most Common CWEs (Top {limit})")
	print("-" * 15)

	for cwe, (c, p) in cwe_count.most_common(limit):
		print(f"{cwe}\t{c}\t{p}")

	#
	# for (_,s, _) in cwes:
	# 	if limit == 0:
	# 		break
	# 	print(s)
		# limit -= 1

	# print("Most Common CWEs by Category")
	# print("-" * 15)
	# for category, data in category_data.items():
	# 	cwe_count = Counter()
	# 	for cwe in data.cwes:
	# 		cwe_count[cwe] += 1
	# 	print(f"{category}")
	# 	for cwe, count in cwe_count.most_common(limit):
	# 		print(f"{cwe}\t{count}")

def print_category_data(category_data: dict[str, CWEData]):
	output = ""

	for category, data in category_data.items():
		output += f"{category}\n{"-" * len(category)}\n"
		for cwe in sorted(data.cwes):
			output += f"{cwe}\n"

	print(output)

def print_projects_rust_cant_prevent(category_data: dict[str, CWEData]):
	projects = set()
	for category in category_data.values():
		projects.update(category.projects)

	not_virtually_impossible = list(filter(lambda x: x not in category_data['Virtually Impossible'].projects, projects))
	filter_out_list = ["Opt-In Measures Only", "Discouraged via Borrow Checker", "Discouraged via Debug Mode", "Virtually Impossible", "Not Categorized"]
	not_prevented_in_rust = set()
	for project in projects:
		found = False
		for category in filter_out_list:
			if project in category_data[category].projects:
				found = True
				break
		if not found:
			not_prevented_in_rust.add(project)

	# print(len(projects), ", ".join(projects))

	# print(f"Projects not Virtually Impossible in Rust ({len(not_virtually_impossible)}):")
	# print("=======================================")
	# print(", ".join(not_virtually_impossible))

	print(f"\nProjects not prevented in Rust ({len(list(not_prevented_in_rust))}):")
	print("=============================")
	print("\n".join(not_prevented_in_rust))

def main():
	rust_csv_data = load_rust_csv()
	load_cwe_variants_map(rust_csv_data)

	cursor = conn.cursor()
	create_c_cwe_project_map(cursor)
	missing_cve_cwe_map = load_c_cve_found_cwe(cursor)

	# Analyze data
	category_data, missing_cwe_data = analyze_data(cursor, rust_csv_data, missing_cve_cwe_map)

	# Analyze prominent projects
	projects_data = dict()
	for project, vp_list in PROMINANT_PROJECTS.items():
		for (vendor, product) in vp_list:
			category_count, unspecified = analyze_single_project(cursor, rust_csv_data, vendor, product, missing_cve_cwe_map, projects_data.get(project))
			projects_data[project] = (category_count, unspecified)

	# Output data
	data_str, unspecified_str, no_cwes = generate_outputs(cursor, category_data, missing_cwe_data, projects_data)
	if OUTPUT_TO_FILE:
		output_data(data_str, unspecified_str, no_cwes)
	else:
		print(data_str)
		print("-"*80)
		print(unspecified_str)
		print("-"*80)
		print(no_cwes)

# PRINT UNIQUE CWES
	# print_unique_cwes(category_data)

# PRINT CATEGORIZED CWE LIST
	# print_category_data(category_data)

# PRINT CVES WITHOUT CWE
	# print(print_cve_no_cwe(cursor)[0])

# PRINT MOST COMMON CWEs
	# print_most_common_cwes(cursor, missing_cve_cwe_map, category_data, rust_csv_data, limit=40)

# PRINT PROJECTS RUST CAN'T PREVENT
	# print_projects_rust_cant_prevent(category_data)
	# cant_prevent = ["libuv/libuv","n/a/Shadowsocks","Apache/Apache Spark","rustdesk/rustdesk","huggingface/huggingface/transformers","SoftEtherVPN/SoftEtherVPN","taosdata/TDengine","Golang/Go","timescale/timescaledb","scikit-learn/scikit-learn/scikit-learn","OpenWRT/OpenWRT",
	# "n/a/go/golang",
	# "[UNKNOWN]/golang",
	# ]
	# get_cwe = """
	# select cwe_id from c_cve_cwe_project where project = %s
	# """

	# for project in cant_prevent:
	# 	cursor.execute(get_cwe, (project,))
	# 	cwes = cursor.fetchall()
	# 	cwes = [cwe[0] for cwe in cwes]
	# 	print(f"{project}: {",".join(set(cwes))}")

# PRINT UNCATAGORIZED CWEs
	# for cwe in list(sorted(missing_cwe_data)):
	# 	print(cwe)

	cursor.close()
	conn.close()


if __name__ == "__main__":
	main()
