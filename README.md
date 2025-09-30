# MegaFoss 
MegaFoss is a project dedicatd to collecting and analyzing vulnerability data from open source software to better understand and improve software security. It provides tools and datasets to map, track and study vulnerabilities across popular projects

# Setup Guide
## Required Programs
- MongoDB Compass (https://www.mongodb.com/try/download/compass) - Gui version - Windows / Linux / Mac
- MongoDB BI Connector (https://www.mongodb.com/try/download/bi-connector) - windows / Linux / Mac
- MongoDB Shell (https://www.mongodb.com/try/download/shell) - Windows / Linux / Mac
- Python 3.11.3 or higher

## Install Python dependencies
In the root folder there is a file called ```requirements.txt```, use the following command to install all the dependencies (venv is recomended)

```
pip install -r requirements.txt
```

## Generate mongo.ini
To facilitate secure and correct connection to MongoDB go to the file ```cd src/cve/config``` inside is going to be a ```mongo.default.ini```. Copy and paste this file in the same folder and change its name to ```mongo.ini```

The file should be with the following format:

```
[DEFAULT]
HOST=localhost
PORT=27017
DATABASE=megafoss
COLLECTION=cves
```
* Adjust the values if your MongoDB instance uses different settings

## Create the views
Some of the scripts need views. To create them, position yourself into ```cd src/cve/``` and then use the follow command:

```
python mg_create_db_views.py
```
* This will generate the different views needed for other scripts

## Obtain and import CVE Data automatically
Go to the file ```/src/cve``` you can use the provided bash script ```import_nvdcve.sh``` which automates the process of importing CVE JSON files

The script will do the following:
- Clone the nvdcve github repository ```https://github.com/olbat/nvdcve``` as a sibling folder next to the mega-foss project if it is not already cloned
- Import all CVE JSON files from the cloned repository into your MongoDB instance

```
./import_nvdcve.sh localhost 27017 megafoss cves C:/projects/RIT/
```

- This command clones nvdcve into ```C:/projects/RIT/``` if missing
- Then imports all JSON files into the ```megafoss``` database and ```cves``` collection at ```localhost:27017```
- The script supports interruption and can be run multiple times without duplicating documents (MongoDB prevents duplicates by _id)
