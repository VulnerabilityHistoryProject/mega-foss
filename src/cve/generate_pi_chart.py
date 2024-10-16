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
from tqdm import tqdm
from enum import Enum
from pathlib import Path
from collections import Counter

# Constants
LIST_OF_PROMINANT_PROJECTS = [ # Stored as (Vendor, Product)
	("Linux", "Linux"),
]

# Input files/folders
c_repos_nvd_csv = os.path.join(os.path.dirname(__file__), '../../lists/c_repos_to_nvd.csv')
rust_cwe_csv = os.path.join(os.path.dirname(__file__), '../../lists/rust_to_cwe.csv')
select_unique_cwe_query = os.path.join(os.path.dirname(__file__), 'queries/select_unique_cwes.sql')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/pi_char_data.txt')
missing_cwe = os.path.join(os.path.dirname(__file__), 'output/pi_chart_missing.txt')

# Connection details
conn = psycopg2.connect(
    dbname="cve_db",
    user="postgres",
    password=PASSWORD,# <--- Change this to your password
    host="localhost"
)

class RustCSVData:
	def __init__(self, cwe_id=None, name=None, classification=None, vote=None, clippy=None):
		self.id = cwe_id
		self.name = name
		self.type = classification
		self.vote = vote
		self.clippy = clippy
		self.cves = set()

	def is_base(self) -> bool:
		return self.type == "Base"

	def __str__(self):
		return f"{self.id}: {self.vote}"

class CWEData:
	def __init__(self):
		self.projects = set()
		self.cves = set()

def load_rust_csv() -> dict[str, RustCSVData]:
	rust_cwe_csv_path = Path(rust_cwe_csv)
	try:
		with open(rust_cwe_csv_path, 'r') as f:
			reader = csv.reader(f)
			next(reader)
			# Headers: CWE-ID,Name,Link,Type,Prohibited?,Description,Vote,Clippy Helps?,Voter's Notes,Assumption,Revisit?,Needs discussion?,GH Issue,GH Issue URL,Rust Docs link
			# Want: CWE-ID,Name,Type,Vote,Clippy Helps?
			return {f"CWE-{r[0]}": RustCSVData(r[0], r[1], r[3], r[6], r[7]) for r in tqdm(reader, desc="Loading Rust CSV Data")}
	except FileNotFoundError:
		print(f"Could not find file: {rust_cwe_csv_path}")
		exit()
	except Exception as e:
		print(f"Error loading file: {e}")
		exit()

def create_c_cwe_project_map(cursor):
	"""
	Creates a temporary table that maps C projects to their CWEs.
	"""
	create_c_table = """
	CREATE TEMP TABLE c_cve_cwe_project AS
		SELECT * FROM cve_cwe_project
		WHERE project=ANY(%s);
		"""

	c_repo_csv_path = Path(c_repos_nvd_csv)
	c_projects = list()

	with open(c_repo_csv_path, 'r') as f:
		reader = csv.reader(f)
		next(reader)
		for r in reader:
			if r:
				c_projects.append(f"{r[1]}/{r[2]}")

	cursor.execute(create_c_table, (c_projects,))
	print("Created C Repos -> CWE -> Project Map")

def analyze_single_project(cursor, rust_cwes: dict[str, RustCSVData], vendor, product):
	project = f"{vendor}/{product}"
	category_count = Counter({
		"No Help, or Langs Won't Help": 0,
		"Opt-In Measures Only": 0,
		"Discouraged via Borrow Checker": 0,
		"Discouraged via Debug Mode": 0,
		"Virtually Impossible": 0,
	})
	unspecified = list()

	select_cwe_query = """
	SELECT * FROM c_cve_cwe_project
	WHERE project=%s
	"""

	cursor.execute(select_cwe_query, (project,))

	for (cve_id, cwe_id, _) in cursor.fetchall():
		if cwe_id in rust_cwes:
			data = rust_cwes[cwe_id]
			if data.is_base():
				category_count[str(rust_cwes[cwe_id].vote)] += 1
			else:
				unspecified.append(cwe_id)
		else:
			unspecified.append(cwe_id)

	return category_count, unspecified

def analyze_data(cursor, rust_cwes:dict[str, RustCSVData]):
	category_data = {
		"No Help, or Langs Won't Help": CWEData(),
		"Opt-In Measures Only": CWEData(),
		"Discouraged via Borrow Checker": CWEData(),
		"Discouraged via Debug Mode": CWEData(),
		"Virtually Impossible": CWEData(),
		"Unspecified": CWEData(),
	}
	missing_cwe_data = dict()

	cursor.execute("SELECT * FROM c_cve_cwe_project")
	for (cve_id, cwe_id, project) in tqdm(cursor.fetchall(), desc="Analyzing CRepo CWE Data"):
		if cwe_id in rust_cwes:
			data = rust_cwes[cwe_id]
			if data.is_base() and data.vote in category_data:
				data = category_data[str(data.vote)]
				data.projects.add(project)
				data.cves.add(cve_id)
			else:
				category_data["Unspecified"].projects.add(project)
				category_data["Unspecified"].cves.add(cve_id)
				if cwe_id not in missing_cwe_data:
					missing_cwe_data[cwe_id] = CWEData()
				data = missing_cwe_data[cwe_id]
				data.projects.add(project)
				data.cves.add(cve_id)

	return category_data, missing_cwe_data


def generate_outputs(category_data, missing_cwe_data, projects_data):
	output = ""
	unspecified = ""

	output += "Category\tProjects\tCVEs\n"
	for category, data in tqdm(category_data.items(), desc="Generating Primary Output"):
		output += f"{category}\t{len(data.projects)}\t{len(data.cves)}\n"

	unspecified += "Missing CWEs\n"
	unspecified += "============\n"
	for cwe, data in tqdm(missing_cwe_data.items(), desc="Generating Missing CWE Output"):
		unspecified += f"{cwe}\t{len(data.projects)}\t{len(data.cves)}\n"

	for project, (category_data, missing) in tqdm(projects_data.items(), desc="Generating Project Output"):
		output += f"\n\n{project}\n"
		output += "=" * len(project) + "\n"
		output += "Category\tCount\n"
		for category, count in category_data.items():
			output += f"{category}\t{count}\n"
		unspecified += "\n\n{project} Unspecified:\n"
		unspecified += "=" * len(project) + "===========\n"
		for cwe in missing:
			unspecified += f"{cwe}\n"
		output += f"Unspecified\t{len(missing)}\n"


	return output, unspecified

def output_data(out_str, missing_str):
	with open(Path(output_file), 'w') as f:
		f.write(out_str)

	with open(Path(missing_cwe), 'w') as f:
		f.write(missing_str)


def main():
	cursor = conn.cursor()
	rust_csv_data = load_rust_csv()
	create_c_cwe_project_map(cursor)

	# Analyze data
	category_data, missing_cwe_data = analyze_data(cursor, rust_csv_data)
	projects_data = dict()
	for (vendor, product) in tqdm(LIST_OF_PROMINANT_PROJECTS, desc="Analyzing Prominent Projects"):
		category_count, unspecified = analyze_single_project(cursor, rust_csv_data, vendor, product)
		projects_data[f"{vendor},{product}"] = (category_count, unspecified)

	# Output data
	data_str, unspecified_str = generate_outputs(category_data, missing_cwe_data, projects_data)
	# output_data(data_str, unspecified_str)
	print(data_str)

	cursor.close()
	conn.close()


if __name__ == "__main__":
	main()
