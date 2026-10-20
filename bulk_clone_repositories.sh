#!/bin/bash
#SBATCH --job-name=clone_repos
#SBATCH --output=clone_repos_%j.out
#SBATCH --error=clone_repos_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=01:00:00
#SBATCH --partition=tier3

source settings.ini

file_with_repositories="$REPOSITORY_LIST"
clone_dir="$REPOSITORIES_PATH"
log_file="output/log.txt"

count_cloned=0
count_updated=0
count_removed=0
current_repo=""

function on_interruption {
  echo "Operation interrupted during processing repository: $current_repo" >> "$log_file"
  echo "----- Log Entry Aborted: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"
  exit 1
}

trap on_interruption INT

echo "----- Log Entry Start: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"

cd "$clone_dir"

# CSV with header "repo,url"; clones to <REPOSITORIES_PATH>/<owner>/<name>
while IFS=, read -r repository repository_url
do
  repository=$(echo "$repository" | tr -d '\r')
  repository_url=$(echo "$repository_url" | tr -d '\r')
  [ -z "$repository" ] || [ "$repository" = "repo" ] && continue
  current_repo="$repository"
  repo_name="$repository"
  mkdir -p "$(dirname "$repo_name")"

  if [ -d "$repo_name" ]; then
    if git -C "$repo_name" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
      echo "Repository '$repo_name' already cloned. Updating..."
      git -C "$repo_name" pull
      ((count_updated++))
    else
      echo "Directory $repo_name exists but is not a git repository. Removing to reclone."
      rm -rf "$repo_name"
      ((count_removed++))
      echo "Cloning repository: $repository_url"
      git clone "$repository_url" "$repo_name"
      ((count_cloned++))
    fi
  else
    echo "Cloning repository: $repository_url"
    git clone "$repository_url" "$repo_name"
    ((count_cloned++))
  fi
done < "$file_with_repositories"

echo "Total repositories cloned: $count_cloned" >> "$log_file"
echo "Total repositories updated: $count_updated" >> "$log_file"
echo "Total repositories removed and recloned: $count_removed" >> "$log_file"
echo "----- Log Entry Completed Successfully: $(date '+%Y-%m-%d %H:%M:%S') -----" >> "$log_file"

echo "Operation completed. Please check the file $log_file for details."
