#!/bin/sh

#SBATCH --job-name=megafoss-clones		# Name for your job
#SBATCH --comment="Cloning the top repos from github locally"

#SBATCH --account=vhp
#SBATCH --partition=debug		# change to tier3 when ready, usually debug

#SBATCH --output=/home/axmvse/logs/%x_%j.out		# Output file
#SBATCH --error=/home/axmvse/logs/%x_%j.err		# Error file

#SBATCH --mail-user=slack:@axmvse	# Slack username to notify
#SBATCH --mail-type=END			# Type of slack notifications to send

#SBATCH --time=0-12:00:00		# 0 days, 12 hour time limit

#SBATCH --nodes=1			# How many nodes to run on
#SBATCH --ntasks=1			# How many tasks per node
#SBATCH --cpus-per-task=1		# Number of CPUs per task
#SBATCH --mem=1g			# Memory per node

echo "Script running!"
date

hostname				# Run the command hostname

spack env activate ~/vhp_env

echo "Spack env activated"
date


cat ./lists/repo_list.txt | while read repo
do
    echo "Cloning $repo"
    git clone --bare https://github.com/$repo.git ~/github/$repo.git
done

wait