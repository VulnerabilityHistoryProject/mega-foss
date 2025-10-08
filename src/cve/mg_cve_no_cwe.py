import os
import re
from config import read_config, mg_connect

cfg = read_config()
database = mg_connect(cfg)
nvdcve_cwe = database.cve_cwe

output_file = os.path.join('output', 'cve_no_cwe.txt')

def main():
    results = nvdcve_cwe.aggregate([
        { '$match': { 'cwe': { '$not': re.compile(r"^CWE") } } }
    ]).to_list()

    with open(output_file, 'w') as f:
        f.writelines(f"{row['cve_id']}\n" for row in results)

    print(f"Found {len(results)} CVEs without CWEs. Results written to {output_file}")

if __name__ == "__main__":
    main()
