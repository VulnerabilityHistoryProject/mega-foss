#!/bin/bash

source settings.ini

if [ ! -d "$NVDCVE_PATH" ]; then
  git clone https://github.com/olbat/nvdcve.git "$NVDCVE_PATH"
fi

for file in "$NVDCVE_PATH"/*.json
do
  mongoimport --host "$HOST" --port "$PORT" \
    --db "$DATABASE" --collection "nvdcve" \
    --type json \
    --file "$file"
done
