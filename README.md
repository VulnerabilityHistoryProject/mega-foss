# MegaFoss 
MegaFoss is a project dedicatd to collecting and analyzing vulnerability data from open source software to better understand and improve software security. It provides tools and datasets to map, track and study vulnerabilities across popular projects

# Setup Guide
## Required Programs
- MongoDB Community Server (https://www.mongodb.com/try/download/database-tools)
- Python 3.11.3 or higher

## Step 1: Obtain CVE Data
- You can get CVE JSON files by clonning the repository:

```
git clone https://github.com/olbat/nvdcve cves
```
* For testing you don't need the full dataset just download or clone a few JSON files

## Step 2: Use MongoDB Compass to Import CVE Data
- Create a new database (e.g. megafoss) and a collection (e.g. cves)
- Inside the collection and import the cves JSON

## Step 3: Install Python Dependencies
- In your megafoss project folder install required Python packages (venv recomended):

```
pip install -r requirements.txt
```

# Using MegaFoss
## mg_repos_to_nvd.py
- Converts the curated repo list into a mapped CSV file connecting CVE vendors and products
- Usage:

```
python src/cve/mg_repos_to_nvd.py
```

## mg_list_patches.py
- outputs lists of Git patches associated with CVEs in the repositories
- Usage:

```
python src/cve/mg_list_patches.py
```

## mg_cve_no_cwe.py
- Creates a list of CVEs that are missing CWE identifiers
- Usage:

```
python src/cve/mg_cve_no_cwe.py
```

## mg_analysis.py
- Performs various analyses on the CVE data including mapping to Rust vulnerability ratings using and external CSV
- Usage:

```
python src/cve/mg_analysis.py
```
