#!/bin/bash -l

#SBATCH --job-name=SUMS

#SBATCH --comment="Calculating sums and matches"

#SBATCH --account=sfs

#SBATCH --partition=tier3

#SBATCH --time=0-01:00:00

#SBATCH --output=production_logs/%x_%j.out

#SBATCH --error=production_logs/%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=ALL

#SBATCH --cpus-per-task=1

#SBATCH --nodes=1

#SBATCH --mem=1g

echo "Script running!"

conda init

conda activate szz-trust-worthy

hostname

python3 /shared/rc/sfs/mega-foss-Trust-Worthy/src/slurm/drill_scripts/data_synthesis/analysis_production_ready/calc_patch_vuln_sums.py