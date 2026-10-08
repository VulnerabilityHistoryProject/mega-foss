#!/bin/bash

# This is a shell script that you can use to import the entire
# OSV.dev for querying
#
# The OSV data dump is here:
#   https://storage.googleapis.com/osv-vulnerabilities/index.html
# The file you want to download is all.zip
# (if it moves, the OSV.dev documentation should show you)
# you can also use the google-cloud sdk to download it:
#   gcloud storage cp gs://osv-vulnerabilities/all.zip .

set -e

# Usage function
show_help() {
    cat << EOF
Usage: $0 <directory_path> <mongo_host> <mongo_port> <mongo_db> <mongo_collection> <num_workers>

Imports OSV vulnerabilities data (all.zip) into MongoDB.

Arguments:
  zip_file          Path to the all.zip file
  mongo_host        MongoDB host address (e.g., localhost, 127.0.0.1)
  mongo_port        MongoDB port (e.g., 27017)
  mongo_db          MongoDB target database name
  mongo_collection  MongoDB target collection name
  num_workers       Number of insertion workers for mongoimport

Options:
  -h, --help        Show this help message and exit

Example:
  $0 /path/to/osv localhost 27017 osv osv 8
EOF
    exit 0
}

# Check for help flags
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

# Ensure all 6 required parameters are provided
if [ "$#" -ne 6 ]; then
    echo "Error: Missing required arguments." >&2
    echo "Expected 6 arguments, but received $#." >&2
    echo "" >&2
    show_help
fi

# Assign positional parameters to variables
ZIP_FILE="$1"
MONGO_HOST="$2"
MONGO_PORT="$3"
MONGO_DB="$4"
MONGO_COLLECTION="$5"
NUM_WORKERS="$6"

# Check if the zip file exists
if [ ! -f "$ZIP_FILE" ]; then
    echo "Error: File '$ZIP_FILE' not found." >&2
    exit 1
fi

echo "Importing OSV data into MongoDB..."
echo "Database: $MONGO_DB | Collection: $MONGO_COLLECTION | Host: ${MONGO_HOST}:${MONGO_PORT}"

# Stream, parse JSON, and import into MongoDB
unzip -p "$ZIP_FILE" \
  | jq -c . \
  | mongoimport --uri "mongodb://${MONGO_HOST}:${MONGO_PORT}" \
      --db "$MONGO_DB" \
      --collection "$MONGO_COLLECTION" \
      --type json \
      --numInsertionWorkers "$NUM_WORKERS"

echo "Import completed successfully."
