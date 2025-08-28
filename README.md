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
python src/cve/mg_repos_to_nvd.py
```
Output will give a CSV file, a file for repos that need manual mapping, and a file for repos that are not found in the NVD database.

### 2. List Git Patches C_Repos CVEs
```sh
python src/cve/mg_list_patches.py
```

Output will print out a list of patches

### 3. List CVEs with no CWEs
```sh
python src/cve/mg_cve_no_cwe.py
```
Output will give a file `cve/output/cve_no_cwe.txt` with a list of CVEs with no CWEs

### 4. Generate Analysis Of CVEs Mapped to Rust Vulnerability Ratings
#### Pre-requisite
Ensure you have the `lists/rust_csv_data.csv` file available, which contains CWEs mapped to Rust vulnerability status.

```sh
python src/cve/mg_analysis.py
```

Output can be configured to print in the console or save to a file as well as printing out CVEs with no CWEs.
Output will print out tab-seperated data to be copied into the spreadsheet which will auto-update the pie chart.
Output will also print out data for specific projects.
Output will also display a list of CWEs that had no vote mapping.

get-local-commits

### 5. Generate a List of Locally Retrievable Commits
#### Pre-requisite
Ensure you are in the RIT Supercomputing cluster or change the filepath on line 35 ("repos_dir = os.path...") to a folder of NVD repositories. 
If you are on the supercomputing cluster, note that there might be an issue with "dubious ownership" in git. To fix this, run
```sh
git config --global --add safe.directory '*'
```

To run this script, run:
```sh
python src/cve/getLocalCommits.py
```

The output will state if a commit is found or not found. It will also state if a repository does not exist. Extra debug statements can be uncommented as well.
The results will be saved in a file called viable_patches.json (our version is stored in src/cve/viable_patches.json). 

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

# RIT Research Computing Info

To get started on RC:

* Make sure you have been added to the RC cluster - Andy should make this request
* Consult the [RC docs](https://research-computing.git-pages.rit.edu/docs/index.html), particularly the Getting Started with Slurm parts 1 and 2.
* Take a look at our shared drive on RC: `/shared/rc/sfs/`. We'll store our repos there.
* Clone this repository in your home directory on RC so you can run your scripts there
