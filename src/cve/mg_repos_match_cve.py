import os
from config import read_config, mg_connect

cfg = read_config()
db = mg_connect(cfg)

c_repolist = cfg.get("REPOSITORIES_FILE_PATH")
output_file = os.path.join("output", "repos_match_cve.csv")
missing_file = os.path.join("output", "repos_match_cve_missing.txt")
fix_file = os.path.join("output", "repos_match_cve_manual_fix.txt")

collection = db.cves

class Repo:
    """Represents a repository and its CVE matches."""
    def __init__(self, name, vendor, repo):
        self.repo = repo
        self.vendor = vendor.strip().lower()
        self.product = name.strip().lower()
        self.cve_matches = set()
        self.semi_matches = set()

def clean(text):
    """Normalize text for comparison."""
    return text.strip().lower().replace("-", "").replace("_", "").replace(".", "").replace(" ", "")

def extract_vendor_product(cpe):
    """Extract vendor and product from CPE string."""
    parts = cpe.split(":")
    if len(parts) > 4:
        return parts[3], parts[4]
    return None, None

def read_repos(path):
    """Read repos from file and return Repo objects."""
    repos = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if "/" not in line:
                continue
            vendor, product = line.split("/", 1)
            repos.append(Repo(product, vendor, line))
    return repos

def build_cve_map():
    """Build a (vendor, product) -> CVEs map from database."""
    mapping = {}
    for entry in collection.find({}, {"id": 1, "configurations": 1}):
        cve_id = entry.get("id")
        if not cve_id:
            continue
        for config in entry.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    vendor, product = extract_vendor_product(cpe.get("criteria", ""))
                    if vendor and product:
                        key = (clean(vendor), clean(product))
                        mapping.setdefault(key, set()).add(cve_id)
    return mapping

def find_matches(repos, cve_map):
    """Find exact and semi matches for each repository."""
    for repo in repos:
        key = (clean(repo.vendor), clean(repo.product))
        if key in cve_map:
            repo.cve_matches = cve_map[key]
        else:
            for (vendor, product), cves in cve_map.items():
                if vendor == key[0] and key[1] in product:
                    repo.semi_matches.add((vendor, product))

def generate_outputs(repos):
    """Generate CSV, missing, and manual fix strings."""
    csv_data = "github repo,cve vendor,cve product,cve ids\n"
    missing = ""
    fix = ""
    for r in repos:
        if r.cve_matches:
            csv_data += f"{r.repo},{r.vendor},{r.product},{' '.join(sorted(r.cve_matches))}\n"
        elif len(r.semi_matches) == 1:
            v, p = r.semi_matches.pop()
            csv_data += f"{r.repo},{v},{p},\n"
        elif len(r.semi_matches) > 1:
            fix += f"{r.repo}:\n{r.semi_matches}\n\n"
        else:
            missing += f"{r.repo}\n"
    return csv_data, missing, fix

def main():
    repos = read_repos(c_repolist)
    print(f"Repos loaded: {len(repos)}")

    cve_map = build_cve_map()
    find_matches(repos, cve_map)

    exact = sum(1 for r in repos if r.cve_matches)
    semi = sum(1 for r in repos if r.semi_matches)
    missing = sum(1 for r in repos if not r.cve_matches and not r.semi_matches)
    print(f"Exact matches: {exact}, Semi matches: {semi}, Missing: {missing}")

    csv_data, missing_data, fix_data = generate_outputs(repos)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(csv_data)
    with open(missing_file, "w") as f:
        f.write(missing_data)
    with open(fix_file, "w") as f:
        f.write(fix_data)
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    main()
