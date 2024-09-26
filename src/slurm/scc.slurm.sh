#!/bin/sh

#SBATCH --job-name=sloc-scc		# Name for your job
#SBATCH --comment="Count lines of code on many repos"

#SBATCH --account=vhp
#SBATCH --partition=tier3		# change to tier3 when ready, usually debug

#SBATCH --output=%x_%j.out		# Output file
#SBATCH --error=%x_%j.err		# Error file

#SBATCH --mail-user=slack:@axmvse	# Slack username to notify
#SBATCH --mail-type=END			# Type of slack notifications to send

#SBATCH --time=0-18:00:00		# 0 days, 18 hour time limit

#SBATCH --nodes=1			# How many nodes to run on
#SBATCH --ntasks=1			# How many tasks per node
#SBATCH --cpus-per-task=1		# Number of CPUs per task
#SBATCH --mem=4g			# Memory per node

echo "Script running!"
date

hostname				# Run the command hostname

spack env activate ~/vhp_env

echo "Spack env activated"
date

SFS_SHARED=/shared/rc/sfs/
# REPO_LIST=./lists/test_repo.txt
REPO_LIST=./lists/c_repos.txt
OUTPUT_DB=$SFS_SHARED/mega-foss-sloc.sqlite

rm $SFS_SHARED/mega-foss-sloc.sqlite

~/scc/scc --format sql --by-file --sql-project "mega-foss" ~/mega-foss | sqlite3 $OUTPUT_DB

cat $REPO_LIST | while read repo
do
    echo "scc'ing $repo"
	~/scc/scc --format "sql-insert" \
			  --by-file \
			  --sql-project "$repo" \
				$SFS_SHARED/mega-foss-repos/$repo | sqlite3 $OUTPUT_DB
done

wait