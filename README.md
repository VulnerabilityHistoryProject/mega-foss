# MegaFoss
Scripts for acquiring our MegaFoss dataset - a curated list of top open source projects that represent modern software development

# Querying for repos

When we want to regenerate our repo list, run this:


```
python .\src\github\get_repo_list.py
```

# Clone the cves repo:

```
git clone https://github.com/CVEProject/cvelistV5 cves
```

# Script SetUp:

## Prerequisites
1. Ensure postgres is installed running
2. Configure your database connection in `src/cve/config/postgres.ini`
3. Ensure you have a python environment installed and activated
4. Install the required packages by running `pip install -r requirements.txt`

## Setting up the database
1. Run the following command to create the database schema:
```
python src/cve/create_db_tables.py
```

## Scripts

### 1. Convert repos list to CVE Vendor Product CSV
```sh
python src/cve/repos_to_nvd.py
```
Output will give a CSV file, a file for repos that need manual mapping, and a file for repos that are not found in the NVD database.

### 2. List Git Patches C_Repos CVEs
```sh
python src/cve/list_patches.py
```

Output will print out a list of patches

### 3. List CVEs for each Vendor
```sh
python src/cve/nvd_to_cve_id_assigner_name.py
```
Output will print out tuples of (cve_id, vendor)


### 4. List CVEs with no CWEs
```sh
python src/cve/cve_no_cwe.py
```
Output will give a file `cve/output/cve_no_cwe.txt` with a list of CVEs with no CWEs

### 5. Generate Analysis Of CVEs Mapped to Rust Vulnerability Ratings
#### Pre-requisite
Ensure you have the 'Master' and 'CWE_Relative_Map' tables from the [spreadsheet](https://docs.google.com/spreadsheets/d/1JGei0TlPjIJVO8E0t_MqQcXFFn-qcEISHLBGJGBJfmQ/edit?gid=929266422#gid=929266422) downloaded
	as `lists/rust_to_cwe.csv` and `lists/cwe_child_map.csv` respectively.
	The former can be downloaded using `python src/cve/download_rust_cve_sheet.py`

```sh
python src/cve/generate_pi_chart.py
```

Output can be configured to print in the console or save to a file as well as printing out CVEs with no CWEs.
Output will print out tab-seperated data to be copied into the spreadsheet which will auto-update the pi chart.
Output will also print out data for specific projects.
Output will also display a list of CWEs that had no vote mapping.
