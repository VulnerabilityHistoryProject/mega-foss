#!/bin/bash
#SBATCH --job-name=clone_repos
#SBATCH --output=clone_repos_%j.out
#SBATCH --error=clone_repos_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=01:00:00

# Command to run the job
# sbatch clone_repos_job.sh

# Command to monitor the job
# squeue -u <username>

file_with_repositories="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../mega-foss-repos" && pwd)/repositories.txt"
clone_dir="$(dirname "$file_with_repositories")"
log_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log.txt"

count_cloned=0
count_updated=0
count_removed=0
IFS=$'\n'
current_repo=""

function on_interruption {
  echo "Operation interrupted during processing repository: $current_repo" >> "$log_file"
  echo "----- Log Entry Aborted: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"
  exit 1
}

trap on_interruption INT

echo "----- Log Entry Start: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"

cd "$clone_dir"

for repository in $(cat "$file_with_repositories")
do
  current_repo="$repository"
  repository_lowercase=$(echo "$repository" | tr '[:upper:]' '[:lower:]')
  repo_name=$(basename "$repository_lowercase")

  if [ -d "$repo_name" ]; then
    if git -C "$repo_name" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
      echo "Repository '$repo_name' already cloned. Updating..."
      git -C "$repo_name" pull
      ((count_updated++))
    else
      echo "Directory $repo_name exists but is not a git repository. Removing to reclone."
      rm -rf "$repo_name"
      ((count_removed++))
      repository_url="https://github.com/$repository_lowercase.git"
      echo "Cloning repository: $repository_url"
      git clone "$repository_url" "$repo_name"
      ((count_cloned++))
    fi
  else
    repository_url="https://github.com/$repository_lowercase.git"
    echo "Cloning repository: $repository_url"
    git clone "$repository_url" "$repo_name"
    ((count_cloned++))
  fi
done

echo "Total repositories cloned: $count_cloned" >> "$log_file"
echo "Total repositories updated: $count_updated" >> "$log_file"
echo "Total repositories removed and recloned: $count_removed" >> "$log_file"
echo "----- Log Entry Completed Successfully: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"

echo "Operation completed. Please check the file $log_file for details."
