#!/bin/bash -l

#SBATCH --job-name=test-analysisNVD

#SBATCH --comment="Analyzing the 13.8-ish vuln commits robustly now"

#SBATCH --account=sfs

#SBATCH --partition=tier3

#SBATCH --time=2-00:10:00

#SBATCH --output=RC_logs/%x_%j.out

#SBATCH --error=RC_logs/%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=<BEGIN,END,FAIL,ALL>

#SBATCH --cpus-per-task=4

#SBATCH --nodes=1

#SBATCH --mem=12g

echo "Script running!"

conda init

conda activate szz-trust-worthy

hostname

python3 /shared/rc/sfs/mega-foss-Trust-Worthy/src/slurm/drill_scripts/data_synthesis/test_analysis.py
