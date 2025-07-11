#!/bin/bash

REPO_URL=$1
BRANCH=${2:-main}

REPO_NAME="src/orchid/tmp/$(basename -s .git "$REPO_URL")" 

git clone --bare "$REPO_URL" "$REPO_NAME.git"
cd "$REPO_NAME.git" || exit 1

# Loop through commits
git rev-list "$BRANCH" | while read commit; do
    tag=$(git describe --tags --abbrev=0 "$commit" 2>/dev/null)

    if [[ -n "$tag" ]]; then
        message=$(git show -s --format=%s "$commit")

        # Output as tab-separated fields (no escaping needed)
        printf '%s\t%s\t%s\n' "$commit" "$message" "$tag"
    fi
done

cd ..
rm -rf "$REPO_NAME.git"