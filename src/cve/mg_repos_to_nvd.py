import os
from config import read_config, mg_connect

cfg = read_config()
database = mg_connect(cfg)

c_repolist = cfg.get('REPOSITORIES_FILE_PATH')

output_file = os.path.join("output", "repos_to_nvd.csv")
missing_file = os.path.join("output", "repos_to_nvd_missing.txt")
fix_file = os.path.join("output", "repos_to_nvd_manual_fix.txt")

collection = database.cves

class Repo:
    def __init__(self, name, vendor, repo):
        self.repo = repo
        self.vendor = vendor.strip().lower()
        self.product = name.strip().lower()
        self.cve_matches = set()
        self.semi_matches = set()

def clean(s):
    return s.strip().lower().replace("-", "").replace("_", "").replace(".", "").replace(" ", "")

def extract_vendor_product_from_cpe(cpe_str):
    parts = cpe_str.split(':')
    if len(parts) > 4:
        return parts[3], parts[4]
    return None, None

def read_repos(path):
    repos = []
    with open(path, "r") as f:
        for line in f:
            line=line.strip()
            if not line or "/" not in line:
                continue
            vendor, product = line.split("/",1)
            repos.append(Repo(product, vendor, line))
    return repos

def find_matches(repos):
    entries = list(collection.find({}, {"id":1, "configurations":1}))
    product_vendor_to_cves = {}

    for entry in entries:
        cve_id = entry.get("id")
        if not cve_id: 
            continue
        for config in entry.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    vendor, product = extract_vendor_product_from_cpe(cpe.get("criteria", ""))
                    if vendor and product:
                        key = (clean(vendor), clean(product))
                        if key not in product_vendor_to_cves:
                            product_vendor_to_cves[key] = set()
                        product_vendor_to_cves[key].add(cve_id)

    for repo in repos:
        key = (clean(repo.vendor), clean(repo.product))
        if key in product_vendor_to_cves:
            repo.cve_matches = product_vendor_to_cves[key]
        else:
            for (vendor, product), cves in product_vendor_to_cves.items():
                if vendor == key[0] and key[1] in product:
                    repo.semi_matches.add((vendor, product))

def generate_outputs(repos):
    output = "github repo,cve vendor,cve product,cve ids\n"
    output_fix = ""
    output_missing = ""
    for repo in repos:
        if len(repo.semi_matches) > 1:
            output_fix += f"{repo.repo}:\n{repo.semi_matches}\n\n"
        elif len(repo.semi_matches) == 1:
            match = repo.semi_matches.pop()
            output += f"{repo.repo},{match[0]},{match[1]},\n"
        elif not repo.cve_matches:
            output_missing += f"{repo.repo}\n"
        else:
            cves_str = " ".join(sorted(repo.cve_matches))
            output += f"{repo.repo},{repo.vendor},{repo.product},{cves_str}\n"
    return output, output_missing, output_fix

def write_outputs(output, missing, fix):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(output)
    with open(missing_file, "w") as f:
        f.write(missing)
    with open(fix_file, "w") as f:
        f.write(fix)

def main():
    repos = read_repos(c_repolist)
    print(f"Repos loaded: {len(repos)}")
    find_matches(repos)
    output, missing, fix = generate_outputs(repos)
    print(f"Exact matches: {len([r for r in repos if r.cve_matches])}")
    print(f"Semi matches: {len([r for r in repos if r.semi_matches])}")
    print(f"Missing matches: {len([r for r in repos if not r.cve_matches and not r.semi_matches])}")
    write_outputs(output, missing, fix)
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    main()
