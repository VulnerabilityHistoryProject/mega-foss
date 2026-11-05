#!/bin/bash -l
#SBATCH --job-name=osv_rust-prospector
#SBATCH --account=sfs
#SBATCH --partition=tigris
#SBATCH --output=logs/%x_%A_%a.out
#SBATCH --error=logs/%x_%A_%a.err
#SBATCH --time=08:00:00             # 6 hours per batch task
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4           # 4 CPUs for process pool
#SBATCH --mem=16G                   # Memory
#SBATCH --array=0-15                # 16 parallel tasks
#SBATCH --mail-user=slack:@rty4159  # Slack notifications via RIT RC email gateway
#SBATCH --mail-type=ALL

mkdir -p logs output

# Load Spack modules / environment
spack unload --all
spack load /kid6nul

# Avoid PyTorch CPU thread contention across multiprocessing workers
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export TOKENIZERS_PARALLELISM=false

# Paths on RIT RC shared filesystem
CSV_PATH="/shared/rc/sfs/osv-rust/jobs/crate_repos.csv"
CVE_DIR="/shared/rc/sfs/osv-rust/advisories"
TARGET_DIR="/shared/rc/sfs/osv-rust/repos"
MODEL_PATH="./models/all-MiniLM-L6-v2"

# Execute batch runner; Python chunks by SLURM_ARRAY_TASK_ID automatically
python3 -u run_slurm_batch.py \
    --csv "$CSV_PATH" \
    --cve-dir "$CVE_DIR" \
    --repos-dir "$TARGET_DIR" \
    --workers "$SLURM_CPUS_PER_TASK" \
    --output-dir output \
    --use-embeddings \
    --embedding-model "$MODEL_PATH"
