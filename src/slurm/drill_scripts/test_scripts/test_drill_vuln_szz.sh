#!/bin/bash -l

#SBATCH --job-name=test_vuln_drill

#SBATCH --comment="Testing the SZZ algo on minimal number of commits for debugging"

#SBATCH --account=sfs

#SBATCH --partition=tier3

#SBATCH --time=1-00:30:00

#SBATCH --output=test_RC_logs/%x_%j.out

#SBATCH --error=test_RC_logs/%x_%j.err

#SBATCH --mail-user=slack:@jmb7342

#SBATCH --mail-type=<BEGIN,END,FAIL,ALL>

#SBATCH --cpus-per-task=1

#SBATCH --nodes=1

#SBATCH --mem=1g

echo "Script running!"

spack env activate -p gitmining-x86_64-24101401

hostname

python3 /shared/rc/sfs/mega-foss/src/slurm/drill_scripts/test_scripts/test_drill.py
 
