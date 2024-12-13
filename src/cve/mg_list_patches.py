import os
from config import mg_connect

# Files/Folders
repos_list_txt = os.path.join(os.path.dirname(__file__),  '../../lists/c_repos.txt')

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/list_patches.txt')

# Connection details
db = mg_connect()
cve_patches = db.cve_patches

def load_repos() -> list[str]:
  """
  Loads list of repos from a text file into a list

  Returns:
  list[str]: List of repos
  """
  repos = []

  with open(repos_list_txt, mode="r") as repos_txt:
    repos = repos_txt.read().splitlines()

  return repos

def get_repos_patches(repos: list[str]) -> set[tuple[str, str, str]]:
  """
  Get patches for each repo in the list of repos stored as a list of tuples (repo, cve, patch)
  """

  # Get only the patches that are for the repos in the repo_list
  c_cve_patches = cve_patches.aggregate([
      {
          '$unwind': {
              'path': '$patches',
              'includeArrayIndex': 'string'
          }
      }, {
          '$match': {
              'patches.0': {
                  '$in': repos
              }
          }
      }
  ]).to_list()

  c_patches = set([
      (c['patches'][0], c['cve_id'], c['patches'][1]) for c in c_cve_patches
  ])

  return c_patches


def main():
  repos = load_repos()
  cve_patches = get_repos_patches(repos)

  print(f"Found {len(cve_patches)} patches for {len(repos)} repos.")

  with open(output_file, 'w') as f:
    cve_patches = sorted(cve_patches)
    for repo, cve, patch in cve_patches:
      f.write(f"{repo}\t{cve}\t{patch}\n")

  print(f"Results written to {output_file}")


if __name__ == "__main__":
  main()
