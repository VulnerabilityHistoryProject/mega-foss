#!/bin/bash
MONGO_HOST=$1
MONGO_PORT=$2
MONGO_DB=$3
MONGO_COLLECTION=$4
BASE_DIR=$5

CLONE_DIR="$BASE_DIR/nvdcve"

if [ ! -d "$CLONE_DIR" ]; then
  git clone https://github.com/olbat/nvdcve.git "$CLONE_DIR"
fi

for file in "$CLONE_DIR/nvdcve"/*.json
do
  mongoimport --host "$MONGO_HOST" --port "$MONGO_PORT" \
    --db "$MONGO_DB" --collection "$MONGO_COLLECTION" \
    --type json \
    --file "$file"
done
