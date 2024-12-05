"""
Given a list of repositories, this script will attempt to match them with the Vendor and Product names from CVE JSONs.
"""

import os
from tqdm import tqdm
from config import mg_connect

# Input files/folders
c_repolist = os.path.join(os.path.dirname(__file__), "../../lists/c_repos.txt")

# Output files
output_file = os.path.join(os.path.dirname(__file__), "output/repos_to_nvd.csv")
missing_file = os.path.join(
    os.path.dirname(__file__), "output/repos_to_nvd_missing.txt"
)
fix_file = os.path.join(os.path.dirname(__file__), "output/repos_to_nvd_manual_fix.txt")

# Connection details
db = mg_connect()
nvdcve_vendor_product_view = db.vendor_product

class Repo:
  """
  Represents a repository with its vendor, product, and CVE matches
  """
  product: str
  vendor: str
  repo: str
  cve_matches: set[str]
  semi_matches: set[tuple] # Must be manually checked

  def __init__(self, name, vendor, repo):
    self.repo = repo
    self.vendor = vendor
    self.product = name
    self.cve_matches = set()
    self.semi_matches = set()


def read_data(repo_list) -> list[Repo]:
    """
    Reads the list of repos from the file into a list of Repo objects
    """
    repos: list[Repo] = list()

    with open(repo_list, "r") as f:
        for repo in f:
            repo = repo.strip()
            vendor, name = repo.strip().split("/")
            repos.append(Repo(name, vendor, repo))

    return repos

def find_repo_matches(repos: list[Repo]):
    """
    Finds vendor, product matches for each repo in the list of repos
    """

    all_entries = list(nvdcve_vendor_product_view.find())
    all_entries = dict({e['product']:e for e in all_entries})

    for repo in repos:
      f = all_entries.get(repo.product.lower(), False)
      if f:
        if f['vendor'] == repo.vendor.lower():
          repo.cve_matches = f['cve_id']
          repo.vendor = f['vendor']
          repo.product = f['product']


    for repo in repos:
      if len(repo.cve_matches) > 0:
        continue
      for v in all_entries.values():
        product = v['product']
        if product and repo.product in product:
          repo.semi_matches.add((v['vendor'], product, v['product']))

def generate_outputs(repos: list[Repo]) -> tuple[str, str, str]:
    output = "github repo,cve vendor,cve product\n"
    output_fix = ""
    output_missing = ""

    for repo in tqdm(repos, desc="Writing outputs"):
      if len(repo.semi_matches) != 0:
        output_fix += f"{repo.repo}:\n{repo.semi_matches}\n\n"
      elif len(repo.cve_matches) == 0:
        output_missing += f"{repo.repo}\n"
      else:
        output += f"{repo.repo},{repo.vendor},{repo.product}\n"

    return output, output_missing, output_fix


def write_output(output, output_missing, output_fix):
    with open(output_file, "w") as f:
        f.write(output)

    with open(missing_file, "w") as f:
        f.write(output_missing)

    with open(fix_file, "w") as f:
        f.write(output_fix)

def main():
    repos = read_data(c_repolist)
    find_repo_matches(repos)
    output, output_missing, output_fix = generate_outputs(repos)
    write_output(output, output_missing, output_fix)


if __name__ == "__main__":
    main()
