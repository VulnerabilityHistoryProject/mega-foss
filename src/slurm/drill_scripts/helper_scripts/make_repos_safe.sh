#!/bin/bash -l

#SBATCH --job-name=makerepossafe

#SBATCH --comment="Removing security measures by "

#SBATCH --account=sfs

#SBATCH --partition=debug

#SBATCH --time=0-00:30:00

#SBATCH --output=%x_%j.out

#SBATCH --error=%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=<BEGIN,END,FAIL,ALL>

#SBATCH --cpus-per-task=1

#SBATCH --nodes=1

#SBATCH --mem=10g

hostname

# Base directory where repositories are stored
REPO_BASE_DIR="/shared/rc/sfs/nvd-all-repos"

# Loop through all directories (repos) under the base directory
for repo in "$REPO_BASE_DIR"/*/*; do
    if [ -d "$repo/.git" ]; then
        echo "Adding $repo to Git safe directory..."
        git config --global --add safe.directory "$repo"
    fi
done
