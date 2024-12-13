"""
This script analyzes CVE and CWE data and provides:
- CVE Distribution: Analyzes and reports the number of CVEs that fall into each Rust safety category
		(e.g. Virtually Impossible, Discouraged via Borrow Checker, etc.)
- Project Coverage: Tracks how many distinct projects have CVEs in each Rust safety category
- Project Analysis: Detailed breakdown of prominent projects (e.g. Linux kernel) showing distribution
		of CVEs across safety categories

Data Analysis :
- Processes CVE/CWE mappings from multiple sources
- Maps CWEs to Rust safety categories based on classification data
- Generates statistical breakdowns by project and category
- Outputs formatted data for visualization and further analysis
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
	# cwe_id,  name,  description,  mitre_url,  vote,  clippy_helps,  rust_docs_links,  notes,
	def __init__(self, cwe_id=None, name=None, classification=None, vote=None, clippy=None, desc=None, url=None, docs=None, notes=None ):
		self.id = cwe_id
		self.name = name
		self.type = classification
		self.vote = vote
		self.clippy = clippy
		self.cves = set()
		self.ref = False # Indicates if an entry is a child of a base class

		self.description = desc
		self.url = url
		self.docs = docs
		self.vote_notes = notes

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
	"""
	Load the Rust CWE classification data from the CSV file.
	Returns a dictionary mapping CWE IDs to RustCSVData objects.
	"""
	rust_cwe_csv_path = Path(rust_cwe_csv)
	try:
		with open(rust_cwe_csv_path, 'r') as f:
			reader = csv.reader(f)
			next(reader) # Skip headers
			# CWE-ID,Name,Link,Type,Non-Base Needs Classification,Prohibited?,Description,Vote,Clippy Helps?,
			data =  {
				f"CWE-{r[0]}":
					RustCSVData(
						cwe_id=r[0],
						name=r[1],
						classification=r[3],
						vote=r[7],
						clippy=r[8],
						desc=r[6],
						url=r[2],
						docs=r[15],
						notes=r[9]
					)
					for r in reader
			}
			return data
	except FileNotFoundError:
		print(f"Could not find file: {rust_cwe_csv_path}")
		exit()
	except Exception as e:
		print(f"Error loading file: {e}")
		exit()

def load_cwe_variants_map(cwe_data):
	"""
	Load the CWE variant mappings and update parent vote information for non-base CWEs.
	"""
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
						continue # Skip base classes
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


def get_cwe_page(
		cwe_id:int =int(),
		name:str =str(),
		description: str=str(),
		mitre_url: str=str(),
		vote: str=str(),
		clippy_helps: bool=bool(),
		rust_docs_links: list[str]=list(),
		notes: str=str()
	):
	return f"""+++
title = "CWE-{cwe_id}: {name}"
description	= "{description}"
weight = {cwe_id}

[extra]
id = {cwe_id}
name = "{name}"
url = "{mitre_url}"
vote = "{vote}"
clippy_helps = {"true" if clippy_helps else "false"}
rust_docs_links = [
	{",\n".join([f'"{link}"' for link in rust_docs_links])}
]
+++
{notes}
"""

def generate_cwe_page_files(rust_csv_data: dict[str, RustCSVData]):
	"""
	Create a file per CWE in /cwes to work with te new zola site
	"""

	for cwe in rust_csv_data.values():
		output_path = Path(os.path.join(os.path.dirname(__file__), f'output/cves/CWE-{cwe.id}.md'))
		data = get_cwe_page(
			cwe_id=cwe.id,
			name=cwe.name,
			description=cwe.description,
			mitre_url=cwe.url,
			vote=cwe.vote,
			clippy_helps=(True if cwe.clippy else False),
			rust_docs_links=(cwe.docs.split(",") if cwe.docs else []),
			notes=cwe.vote_notes
		)

		with open(output_path, 'w') as f:
			f.write(data)


def main():
	rust_csv_data = load_rust_csv()
	load_cwe_variants_map(rust_csv_data)

	cursor = conn.cursor()
	create_c_cwe_project_map(cursor)
	missing_cve_cwe_map = load_c_cve_found_cwe(cursor)

	# Analyze data
	category_data, missing_cwe_data = analyze_data(cursor, rust_csv_data, missing_cve_cwe_map)

	# Analyze prominent projects
	# projects_data = dict()
	# for project, vp_list in PROMINANT_PROJECTS.items():
	# 	for (vendor, product) in vp_list:
	# 		category_count, unspecified = analyze_single_project(cursor, rust_csv_data, vendor, product, missing_cve_cwe_map, projects_data.get(project))
	# 		projects_data[project] = (category_count, unspecified)

	# Output data
	# data_str, unspecified_str, no_cwes = generate_outputs(cursor, category_data, missing_cwe_data, projects_data)
	# if OUTPUT_TO_FILE:
	# 	output_data(data_str, unspecified_str, no_cwes)
	# else:
	# 	print(data_str)
	# 	print("-"*80)
	# 	print(unspecified_str)
	# 	print("-"*80)
	# 	print(no_cwes)

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

# PRINT UNCATAGORIZED CWEs
	# for cwe in list(sorted(missing_cwe_data)):
	# 	print(cwe)
	#

# Generate Files for Website
	# generate_cwe_page_files(rust_csv_data)

	cursor.close()
	conn.close()


if __name__ == "__main__":
	main()
