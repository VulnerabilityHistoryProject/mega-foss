
#!/bin/bash

# This is a shell script that you can use to import the entire
# OSV.dev for querying
#
# The OSV data dump is here:
#   https://storage.googleapis.com/osv-vulnerabilities/index.html
# The file you want to download is all.zip
# (if it moves, the OSV.dev documentation should show you)
#
# Unzip that all.zip (I recommend 7-zip instead of Windows' built-in zip)

# Set the path to the directory containing the JSON/CSV files
directoryPath=

# Set the MongoDB connection details
mongoHost=localhost
mongoPort=27017
mongoDatabase=osv
mongoCollection=osv

for file in $directoryPath
do
	mongoimport --uri "mongodb://localhost:27017" \
		--db $mongoDatabase \
		--collection $mongoCollection \
		--type json \
		--file $file
done