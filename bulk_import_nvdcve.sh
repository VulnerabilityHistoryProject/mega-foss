#!/bin/bash
#SBATCH --job-name=clone_repos
#SBATCH --output=clone_repos_%j.out
#SBATCH --error=clone_repos_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=01:00:00
#SBATCH --partition=tier3

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
