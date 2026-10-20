#!/bin/bash -l

# Submit with one array task per line of the vulnerability list:
#   VULN_LIST=lists/osv_vulns.txt
#   sbatch --array=1-$(wc -l < $VULN_LIST) src/slurm/fix_tracer.slurm.sh $VULN_LIST
# Use --array=1-N%20 to cap concurrent tasks.

#SBATCH --job-name=fix-tracer
#SBATCH --comment="Map each OSV vulnerability to its fix commit"
#SBATCH --account=vhp
#SBATCH --partition=tier3
#SBATCH --time=0-04:00:00
#SBATCH --output=fix_tracer_logs/%x_%A_%a.out
#SBATCH --error=fix_tracer_logs/%x_%A_%a.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=16g

VULN_LIST=${1:?usage: sbatch --array=1-N fix_tracer.slurm.sh <vuln-list.txt>}
VULN_ID=$(sed -n "${SLURM_ARRAY_TASK_ID}p" "$VULN_LIST" | tr -d '[:space:]')

if [ -z "$VULN_ID" ]; then
    echo "No vulnerability on line ${SLURM_ARRAY_TASK_ID} of $VULN_LIST"
    exit 1
fi

spack env activate ~/vhp_env

echo "Tracing $VULN_ID on $(hostname)"
python3 src/osv/fix_tracer.py "$VULN_ID" "${@:2}"
