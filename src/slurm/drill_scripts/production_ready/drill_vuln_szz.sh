#!/bin/bash -l

#SBATCH --job-name=NVD-Vuln-drill-frfr

#SBATCH --comment="Running pydriller SZZ on the NVD repos to get the vuln commit that matches the patch commit"

#SBATCH --account=sfs

#SBATCH --partition=tier3

#SBATCH --time=1-00:00:00

#SBATCH --output=RC_logs/%x_%j.out

#SBATCH --error=RC_logs/%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=<BEGIN,END,FAIL,ALL>

#SBATCH --cpus-per-task=1

#SBATCH --nodes=1

#SBATCH --mem=10g

echo "Script running!"

spack env activate -p gitmining-x86_64-24101401

hostname

python3 /shared/rc/sfs/mega-foss/src/slurm/drill_scripts/production_ready/drill_14k.py