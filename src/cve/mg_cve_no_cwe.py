"""
This script finds all CVEs that do not have a CWE associated with them.
"""

import os
import re
from config import mg_connect

# Output files
output_file = os.path.join(os.path.dirname(__file__), 'output/cve_no_cwe.txt')

# Connection details
db = mg_connect()
nvdcve_cwe = db.cve_cwe

def main():
  # Filter out CWES that start with "CWE" from CVE, CWE view
  results = nvdcve_cwe.aggregate([
      {
          '$match': {
              'cwe': { '$not': re.compile(r"^CWE") }
          }
      }
  ]).to_list()

  with open(output_file, 'w') as f:
    for row in results:
      f.write(f"{row['cve_id']}\n")

  print(f"Found {len(results)} CVEs without CWEs. Results written to {output_file}")


if __name__ == "__main__":
  main()
