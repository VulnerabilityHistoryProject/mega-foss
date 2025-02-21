#!/bin/bash -l

#SBATCH --job-name=SZZdataanalysis

#SBATCH --comment="Analyzing the 13.8-ish vuln commits now"

#SBATCH --account=sfs

#SBATCH --partition=tier3

#SBATCH --time=0-10:00:00

#SBATCH --output=%x_%j.out

#SBATCH --error=%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=<BEGIN,END,FAIL,ALL>

#SBATCH --cpus-per-task=1

#SBATCH --nodes=1

#SBATCH --mem=10g

echo "Script running!"

conda init

conda activate szz-trust-worthy

hostname

python3 /shared/rc/sfs/mega-foss-Trust-Worthy/src/slurm/drill_scripts/data_synthesis/analysis.py