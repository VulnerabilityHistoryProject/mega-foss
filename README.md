# MegaFoss 
MegaFoss is a project dedicatd to collecting and analyzing vulnerability data from open source software to better understand and improve software security. It provides tools and datasets to map, track and study vulnerabilities across popular projects

# Setup Guide
## Required Programs
- MongoDB Compass (https://www.mongodb.com/try/download/compass) - Gui version - Windows / Linux / Mac
- MongoDB Shell (https://www.mongodb.com/try/download/shell) - Windows / Linux / Mac
- MongoDB Tools (https://www.mongodb.com/try/download/database-tools) - Windows / Linux / Mac
- Python 3.11.3 or higher

## Install Python dependencies
In the root folder there is a file called ```requirements.txt```, use the following command to install all the dependencies (venv is recomended)

```
pip install -r requirements.txt
```

## Create mongo database
### MongoDB Shell
Run the following command in your terminal to ensure the MongoDB database exists and the main collection cve is created:

```
mongosh
```

Then in the Mongo shell:

```
use megafoss
db.createCollection("cves")
```

### MongoDB Compass
Open MongoDB compass and connect to your local MongoDB instance using:

```
Hostname: localhost
Port: 27017
```

Once connected you can explore the databse and the collection

## Create settings.ini
To configure the project copy the template file ```settings.default.ini``` from the root folder and rename it to settings.ini. Then update the values according to your environment

The file should look like this:

```
DATABASE="megafoss"
HOST="127.0.0.1"
PORT="27017"
REPOSITORIES_PATH="D:/path/to/repos/folder"
REPOSITORIES_FILE_PATH="C:/path/to/repos/lists/repositories.txt"
NVDCVE_PATH="E:/path/to/nvdcve/files"
```

## Obtain and import CVE data
First clone the nvdcve github repository: 

```
https://github.com/olbat/nvdcve
```

Then run the provided bash script from the project root to import the CVE data:

```
bulk_import_nvdcve.sh
```

## Clone repositories
Create a folder named ```mega-foss-repositories``` as a sibling to the project folder. The ```repositories.txt``` contains a list of repositories that would be used after clonning them to match with the different NVDCVEs that are inside the database

To clone all the resporitories from the ```repositories.txt``` run the following command:

```
bash bulk_clone_repositories.sh
```

# Scripts
## Match repositories with CVEs
The script with name ```mg_repos_match_cve ``` will match the CVEs inside the database with the different repos that we have inside ```mega-foss-repositories```

To run the script, which is located in ```src/cve```, use the following command:

```
python -m src.cve.mg_repos_match_cve
```

# Outputs
All outputs from the project would be inside the root folder ```output```
