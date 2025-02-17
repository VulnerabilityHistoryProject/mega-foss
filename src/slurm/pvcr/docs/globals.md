## Global Variables

### `PATH_ALL_PROJ_REPOS` (str)
Path to the directory containing all the FOSS project git repos.

### `PATH_SELECTED_REPO` (str)
Path to the specific repo. This changes as the script iterates through the different patch commits in the JSON file.

### `PATH_PATCH_COMMITS` (str)
Path to the JSON file containing all of the patch commits that fix vulnerabilities.

### `PATH_OUTPUT_DIR` (str)
Path to the output directory where the JSON file with vulnerable commits will be written to.

### `PATH_LOG_OUTPUT_DIR` (str)
Path to the output directory where the logs and errors will be stored.

### `HASH_PATCH_COMMIT` (str)
Commit hash of the patch commit to a vulnerability.

### `HASH_VULN_COMMIT` (str)
Commit hash of the original commit that introduced the vulnerability.

### `MOD_FILES_BY_PATCH` set[str]
Set of paths to files modified by the patch commit.

### `CHANGES_PATCH_COMMIT` dict[str, dict[str, list[tuple[int, str]]]]
The key of the outer dictionary is the name of the modified file by the patch commit. The value is another dictionary. The second dictionary has two keys: "added" or "deleted". 
- The "added" section has the code that was added by the commit.
- The "deleted" section has the code that was removed by the commit.

The changes are in a list of tuples where the first index of the tuple is the line number, and the second index is the code change.

### `CHANGES_VULN_COMMIT` dict[str, dict[str, list[tuple[int, str]]]]
The key of the dictionary is the modified file by the suspected vulnerable commit. The value is another dictionary. The second dictionary has two keys: "added" or "deleted". 
- The "added" section has the code that was added by the commit.
- The "deleted" section has the code that was removed by the commit.

The changes are a code snippet for verification and validation purposes against the `CHANGES_PATCH_COMMIT`. The changes are in a list of tuples where the first index of the tuple is the line number, and the second index is the code change.
