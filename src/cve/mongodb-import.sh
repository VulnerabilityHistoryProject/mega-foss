#!/bin/bash

# Set the path to the directory containing the JSON/CSV files
directoryPath=~/code/nvdcve/nvdcve/*.json

# Set the MongoDB connection details
mongoHost=localhost
mongoPort=27017
mongoDatabase=nvdcve
mongoCollection=nvdcve

for file in $directoryPath
do
	mongoimport --uri "mongodb://localhost:27017" \
		--db $mongoDatabase \
		--collection $mongoCollection \
		--type json \
		--file $file
done
