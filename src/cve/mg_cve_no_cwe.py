import os
import re
from config import read_config, mg_connect

cfg = read_config()
db = mg_connect(cfg)

collection = db.cve_cwe

output_file = os.path.join("output", "cve_no_cwe.txt")

def get_cves_without_cwe():
    """
    Returns a list of CVE IDs that do not have a valid CWE.
    """
    query = {"$match": {"cwe": {"$not": re.compile(r"^CWE")}}}
    results = collection.aggregate([query]).to_list()
    return [row["cve_id"] for row in results]

def save_to_file(cve_ids, path):
    """
    Saves a list of CVE IDs to a text file.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for cve_id in cve_ids:
            f.write(f"{cve_id}\n")

def main():
    cves = get_cves_without_cwe()
    save_to_file(cves, output_file)
    print(f"Found {len(cves)} CVEs without CWEs. Results written to {output_file}")

if __name__ == "__main__":
    main()
