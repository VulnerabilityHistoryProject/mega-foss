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

# Set Up With MongoDB

## Scripts

### 1. Load CVEs into a MongoDB database
#### Pre-requisite
Install MongoDB to your system, or have access to a system running MongoDB. You will also need to install the official toolkit [here](https://www.mongodb.com/try/download/database-tools). Once both downloads are ready, add their `bin`s to your Path or PATH environment variable. These should look something like `{install location}/MongoDB/Server/{version number}/bin` and `{install location}/MongoDB/Tools/{version number}/bin` respectively.
Additionally, if you haven't already, download a collection of CVEs to use. We recommend cloning [this repository](https://github.com/olbat/nvdcve) for a wide range of CVEs, but be warned that it is very large (277k+ CVEs at time of writing)!
#### Steps
Open a command line window and type `mongod --dbpath="{desired database folder location}"`. This should start running a MongoDB instance on your computer at `localhost:27017`. If you would like to use a database that is already running, skip this step. If you would like to use a more complicated configuration, such as on a different port, refer to the mongod documentation [here](https://www.mongodb.com/docs/manual/reference/program/mongod/). Once your database is running, *DO NOT CLOSE THIS WINDOW* until you are done, as this will close your database to connections.
Open either `src/cve/mongodb-import.ps1` or `src/cve/mongodb-import.sh`, whichever seems more appropriate for your system. Replace the default directory path with the path to your CVE collection folder. If you used the default configuration provided by `mongod`, this is all that needs to be changed. If the target database is not on localhost and/or is running on a different port than the default, you will need to change the `mongoHost` and `mongoPort` fields respectively.
Once your chosen script is set up for your system, you can open a new terminal window and run it. Be warned that if your CVE collection is very large, this may take a long time to run!
