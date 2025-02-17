#!/bin/bash -l

#SBATCH --job-name=NVD-Vuln-drill

#SBATCH --comment="Running pydriller SZZ on the NVD repos to get the vuln commit that matches the patch commit"

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

python3 