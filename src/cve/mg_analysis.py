import os
import csv
import copy
from enum import Enum
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse
import orjson
from config import mg_connect
from typing import Self

from mg_cve_impact import vector_to_dict, json_to_vector


# Input files
repos_nvd_csv = os.path.join(os.path.dirname(__file__), '../../lists/c_repos_to_nvd.csv')
rust_cwe_csv = os.path.join(os.path.dirname(__file__), '../../lists/rust_csv_data.csv')

# This file unions all other pipelines over cve_id.
cve_map_json = os.path.join(os.path.dirname(__file__), '../../lists/nvdcve_cve_map.json')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/analysis.txt')

# Connection details
db = mg_connect()

class Project:
	"""_summary_
		Represents a project that is affected by a CVE.
		Either matched via vendor product or by the repo.
	"""
	def __init__(self, repo:str, vendor:str, product:str, patches:list):
		self.repo: str = repo
		self.vendor: str = vendor
		self.product: str = product
		self.patches: list[str] = []

class CVE:
	def __init__(self, cve_id, vector, projects: list[Project]):
		self.id = cve_id
		self.vector = vector
		self.projects: list[Project] = projects or list()

class CWE:
	"""_summary_
	Stores the rust vote information as well as mapped cves from the nvdlist
	"""
	def __init__(self, cwe:int=int(), name:str=str(), cwe_type:str=str(), vote:str=str(), parent:int=int()):
		self.id = cwe
		self.name = name
		self.type = cwe_type
		self.vote = VoteClassifications.from_num(vote)
		self.parent = parent
		self.cves: dict[str, CVE] = dict()


def load_rust_cwe_data() -> dict[str, CWE]:
  """
  Loads the rust voter cwe information
  :return: A dictionary of CWE objects.
  """
  with open(rust_cwe_csv, mode="r") as rust_cwe_file:
    rust_cwe_data = csv.DictReader(rust_cwe_file)
    data = {}
    for row in rust_cwe_data:
      parent = int(row['Parent']) if row['Parent'] else 0
      cwe = CWE(int(row['CWE']), row['Name'], row['Class'], row['Vote'], parent)
      data[f"CWE-{row['CWE']}"] = cwe
    return data


def load_project_data(cwe_data):
	""""_summary_"
	Loads the nvd cwe inforation into the cwe_data object.

	Takes the projects from repo_to_nvd list and matches them
	to CVEs in the CVElist then maps them to the previously stored CWEs.

	Args:
			cwe_data (_type_):
	"""
	# Load the cve map (Much faster to export than quering mongo)
	cve_map = None
	with open(cve_map_json, mode="r") as cve_map_file:
		cve_map = orjson.loads(cve_map_file.read())

	warn = set()
	with open(repos_nvd_csv, mode="r") as c_project_file:
		c_project_data = csv.DictReader(c_project_file)
		vp_projects = {} # Projects map via vendor product
		rp_projects = {} # Projects map via repo

		# Create project objects and maps
		for row in c_project_data:
			repo, vendor, product = row['github repo'], row['cve vendor'], row['cve product']
			c_project = Project(repo, vendor, product, patches=None)
			vp_projects[(vendor, product)] = c_project
			rp_projects[repo] = c_project

		# Add the project to the cwe data
		for cve in cve_map:
			# Skip cves without a cwe
			cve_id, cwe_id = cve['cve_id'], cve.get('cwe')
			if not cwe_id or not cwe_id.startswith('CWE-'):
				continue
			cwe: CWE = cwe_data.get(cwe_id)
			if not cwe:
				if cwe_id not in warn:
					warn.add(cwe_id)
					# print(f"WARNING: Could not find CWE {cwe_id}")
				continue

			vector = cve.get('metrics', {}).get('vector', "")
			vendor, product = cve.get('vendor', ""), cve.get('product', "")
			patches = cve['patches']
			project = None

			# Match nvd projects to repo_list projects
			# via vendor product or repo
			if (vendor, product) in vp_projects:
				project = vp_projects[(vendor, product)]
			else:
				for url in patches:
					url_repo = "/".join(urlparse(url).path.split("/")[1:3])
					if url_repo in rp_projects:
						project = rp_projects[url_repo]
						break

			if not project:
				continue

			# Add the project to the cve and cve to the cwe
			project.patches = patches
			if cve_id in cwe.cves:
				cwe.cves[cve_id].projects.append(project)
			else:
				cve_data = CVE(cve_id, vector, [project])
				cwe.cves[cve_id] = cve_data

class VoteClassifications:
	"""_summary_
		Represents the different classifications of votes for a CWE.
		In the CWE Markdowns these votes are stored as a dict, and in the CSV they are stored as a 8-digit bit-number.
	"""
	def __init__(self):
		self.virtually_impossible = False
		self.discouraged = False
		self.discouraged_library = False
		self.discouraged_borrow_checker = False
		self.discouraged_debug_mode = False
		self.clippy = False
		self.no_help = False

	def no_vote(self) -> bool:
		return not any([
			self.virtually_impossible,
			self.discouraged,
			self.discouraged_library,
			self.discouraged_borrow_checker,
			self.discouraged_debug_mode,
			self.clippy,
			self.no_help
		])

	@classmethod
	def keys(cls):
		return cls().to_dict().keys()

	@classmethod
	def from_num(cls, num):
		self = cls()
		self.virtually_impossible = bool(int(num[0]))
		self.discouraged = bool(int(num[1]))
		self.discouraged_library = bool(int(num[2]))
		self.discouraged_borrow_checker = bool(int(num[3]))
		self.discouraged_debug_mode = bool(int(num[4]))
		self.clippy = bool(int(num[5]))
		self.no_help = bool(int(num[6]))
		return self


	def to_num(self):
		return f"{int(self.virtually_impossible)}{int(self.discouraged)}{int(self.discouraged_library)}{int(self.discouraged_borrow_checker)}{int(self.discouraged_debug_mode)}{int(self.clippy)}{int(self.no_help)}"

	def to_dict(self):
		return {
			"No Help, or Langs Won't Help": self.no_help,
			"Discouraged": self.discouraged,
			"Discouraged via Library": self.discouraged_library,
			"Discouraged via Borrow Checker": self.discouraged_borrow_checker,
			"Discouraged via Debug Mode": self.discouraged_debug_mode,
			"Discouraged via Clippy": self.clippy,
			"Virtually Impossible": self.virtually_impossible,
			"Unvoted": None
		}

class CVE_Analysis:
	"""_summary_
	This is designed to analyze the rust CWE data in a chainable manner
	providing methods to calculate and output various statistics related to CVEs, CWEs, projects, and
	voting categorizations.
	"""
	def __init__(self, cwe_data):
		self._total_cves: int
		self._cwes_no_cve: list[str]
		self._unique_cwes: set[str]
		self._total_unique_projects: set[str]
		self._unvoted_cwes: dict[str, list[str]]
		self._categorzied_cwes: dict[str, dict] = None
		self._most_common_cwes: list[str]
		self._projects_rust_cant_prevent: list[str]
		self.cwe_data = cwe_data
		self.output = ""

	def add_output(self, *out, header: str = ""):
		self.output += (f"\n{header}\n{'-'*len(header)}\n")
		for o in out:
			self.output += str(o)
		self.output += "\n"

	def total_cves(self, output=True, by_category=False) -> Self:
		"""
		Calculate the total number of CVEs either overall or by category.

		Args:
			by_category (bool): If True, the CVEs will be counted by category. Default is False.
		"""
		# Count total cves
		if not by_category:
			total_cves = 0
			for cwe in self.cwe_data.values():
				total_cves += len(cwe.cves)

		# Count cves by category
		else:
			if not self._categorzied_cwes:
				self.categorzied_cwes(False)
			categories = {key: 0 for key in VoteClassifications.keys()}
			for category, cwes in self._categorzied_cwes.items():
				categories[category] = sum([len(cwe.cves) for cwe in cwes])
			total_cves = categories

		self._total_cves = total_cves
		if output:
			self.add_output(total_cves, header="Total CVEs")
		return self

	def cwes_no_cve(self, output=True) -> Self:
		"""
		Identify CWEs that do not have any associated CVEs.
		"""
		cwes_no_cve = []

		for cwe in self.cwe_data.values():
			if not cwe.cves:
				cwes_no_cve.append(cwe.id)

		self._cwes_no_cve = cwes_no_cve
		if output:
			self.add_output(cwes_no_cve, header="CWES with no CVEs")
		return self

	def unique_cwes(self, output=True) -> Self:
		"""
		Finds and stores unique CWEs from the cwe_data.
		"""
		unique_cwes = set()
		for cwe in self.cwe_data.values():
			unique_cwes.add(cwe.id)

		self._unique_cwes = unique_cwes
		if output:
			self.add_output(unique_cwes, header="Unique CWEs")
		return self

	def total_unique_projects(self, by_category=False, output=True) -> Self:
		"""
		Calculate the total number of unique projects across all CVEs.
		This method counts unique projects either across all CWEs or categorized by CWE classifications.
		Args:
			by_category (bool, optional): If True, returns counts grouped by CWE categories.
										 If False, returns total unique count. Defaults to False.
		"""
		unique_projects = set()

		# Count unique projects across all CWEs
		if not by_category:
			for cwe in self.cwe_data.values():
				for cve in cwe.cves.values():
					unique_projects.update(cve.projects)
			unique_projects = len(unique_projects)
		# Count unique projects by category
		else:
			self.categorzied_cwes(False)
			categories = {key: set() for key in VoteClassifications.keys()}
			for category, cwes in self._categorzied_cwes.items():
				for cwe in cwes:
					for cve in cwe.cves.values():
						categories[category].update(cve.projects)
				categories[category] = len(categories[category])
			unique_projects = categories

		self._total_unique_projects = unique_projects
		if output:
			self.add_output(unique_projects, header="Total Unique Projects")
		return self

	def unvoted_cwes(self, output=True) -> Self:
		"""
		Finds and stores CWEs that have not been voted on.
		"""
		unvoted_cwes = {}

		for cwe in self.cwe_data.values():
			if cwe.vote.no_vote():
				unvoted_cwes[cwe.id] = cwe

		self._unvoted_cwes = unvoted_cwes
		if output:
			self.add_output(unvoted_cwes, header="Unvoted CWEs")
		return self

	def categorzied_cwes(self, output=True) -> Self:
		"""
		Categorizes CWE data based on vote classifications and stores results.
    The categories are based on VoteClassifications keys and include:
		- Virtually Impossible
		- No Help, or Langs Won't Help
		- Discouraged
		- Discouraged via Library
		- Discouraged via Borrow Checker
		- Discouraged via Debug Mode
		- Discouraged via Clippy
		- Unvoted
		"""
		categorzied_cwes = {key: [] for key in VoteClassifications.keys()}
		c = 0
		for cwe in self.cwe_data.values():
			c += 1
			vote = cwe.vote
			if vote.virtually_impossible:
				categorzied_cwes["Virtually Impossible"].append(cwe)
			if vote.no_help:
				categorzied_cwes["No Help, or Langs Won't Help"].append(cwe)
			if vote.discouraged:
				categorzied_cwes["Discouraged"].append(cwe)
			if vote.discouraged_library:
				categorzied_cwes["Discouraged via Library"].append(cwe)
			if vote.discouraged_borrow_checker:
				categorzied_cwes["Discouraged via Borrow Checker"].append(cwe)
			if vote.discouraged_debug_mode:
				categorzied_cwes["Discouraged via Debug Mode"].append(cwe)
			if vote.clippy:
				categorzied_cwes["Discouraged via Clippy"].append(cwe)
			if vote.no_vote():
				categorzied_cwes["Unvoted"].append(cwe)
		self._categorzied_cwes = categorzied_cwes
		if output:
			self.add_output(categorzied_cwes, header="Categorized CWEs")
		return self

	def most_common_cwes(self, limit=40, output=True) -> Self:
		if not self._categorzied_cwes:
			self.total_cves(by_category=True, output=False)
			self.total_unique_projects(output=False)

		# Count the number of cves and projects for each cwe to determine the most common
		cwe_count = Counter({
    	cwe:
				(len(cwe.cves),
					len(set([project for cve in cwe.cves.values() for project in cve.projects])))
						for cwe in self.cwe_data.values()})

		most_common_cwes = cwe_count.most_common(limit)

		# Formatted output
		o = ""
		for cwe, (c, p) in most_common_cwes:
			o += (f"CWE-{cwe.id}\t{c}\t{p}\n")

		self._most_common_cwes = most_common_cwes
		if output:
			self.add_output(o, header=f"Most Common CWEs (Top {limit})")
		return self

	def projects_rust_cant_prevent(self, output=True) -> Self:
		"""
		Calculate and store projects where Rust cannot prevent vulnerabilities.
		"""
		if not self._categorzied_cwes:
			self.categorzied_cwes(output=False)

		projects = set([project.repo for cwe in self._categorzied_cwes["Virtually Impossible"] for cve in cwe.cves.values() for project in cve.projects])

		# Remove projects that arent in the virtuall impossible category
		illegal_projects = set()
		for category in self._categorzied_cwes:
			if category == "Virtually Impossible":
				continue
			for cwe in self._categorzied_cwes[category]:
				for cve in cwe.cves.values():
					illegal_projects.update([project.repo for project in cve.projects])
		projects = projects - illegal_projects

		self._projects_rust_cant_prevent = projects
		if output:
			self.add_output(projects, header="Projects Rust Can't Prevent")
		return self

	def pi_chart(self, output=True) -> Self | str:
		"""
		Generates a pi chart string representation of CVE data categorized by CWE types.

		If output flag is True, adds the chart to internal output buffer and returns self.
		If output flag is False, returns the chart as a string.

		The chart includes three columns:
		- Category: The CWE category
		- Projects: Number of unique projects affected in that category
		- CVEs: Total number of CVEs in that category

		Example:
			>>> analyzer.pi_chart()
			Category    Projects    CVEs
			Virtuall..     12          45
			No help from..      8           23
			...
		"""
		pi_chart = "Category\tProjects\tCVEs\n"
		# Category, #Projects, #Cves
		self.total_cves(by_category=True, output=False)
		self.total_unique_projects(by_category=True, output=False)
		for category in self._categorzied_cwes:
			pi_chart += f"{category}\t{self._total_unique_projects[category]}\t{self._total_cves[category]}\n"
		if output:
			self.add_output(pi_chart, header="Pi Chart")
			return self
		else:
			return pi_chart

	def print(self):
		print(self.output)
		return self

	def write(self, file: str = output_file):
		with open(file, 'w') as f:
			f.write(self.output)
		return self

def main():
	rust_cwe_data = load_rust_cwe_data()
	load_project_data(rust_cwe_data)
	analyzer = CVE_Analysis(rust_cwe_data)

	(
   analyzer
   	.total_unique_projects(by_category=True)
		.pi_chart()
		.print()
	)


if __name__ == "__main__":
  main()
