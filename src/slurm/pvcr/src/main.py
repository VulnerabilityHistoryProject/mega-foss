import src.configuration.script_setup as script_setup
import src.cve_utils.cve_config as cve_config
import src.szz_utils.szz as szz
import src.error_handling.handle_errors as handle


import logging
import json
import ijson

from typing import Any,Generator


basic_logger = logging.getLogger("basic_logger")
robust_logger = logging.getLogger("robust_logging")

def stream_json_entries(json_file_path: str) -> Generator[dict[str, Any], None, None]:
    """Generator that yields each entry from a JSON list one by one."""
    with open(json_file_path, "r", encoding="utf-8") as f:
        data: list[dict[str, Any]] = json.load(f)  # Explicitly defining type as a list of dictionaries
        for entry in data:
            yield entry  # Yielding each entry one by one


def process_JSON_CVE(json_file_path: str) -> cve_config.CVE:

    processed_cve_id: set[str] = set() # o(1) lookup

    cve_data: Generator = stream_json_entries(json_file_path)

    for cve_entry in cve_data:

        json_cve_id: str = handle.safe_dict_get(cve_entry,"cve_id")
        partial_repo_path: str = handle.safe_dict_get(cve_entry,"repo")
        hash_patch_commit: str = handle.safe_dict_get(cve_entry,"commit")

        if json_cve_id not in processed_cve_id:
            ## How can I associate the cve id with the existing CVE and corresponding cve object?
            ## Create a class that has certain flags set for the type of vulnerability
            ## maybe CVE inherits from a Vulnerability class!

            # Create a new instance of the cve class
            cve_vuln: cve_config.CVE = cve_config.CVE(json_cve_id,partial_repo_path,hash_patch_commit)

            # Set the id field of cve_vuln
            cve_vuln.cve_id = json_cve_id

            processed_cve_id.add(json_cve_id)
        else: # what happens if the cve id is already in the set
            # don't create a new cve object, rather add the hash patch commit to the list from the patch commits class
            # CVE class should have a list 



if __name__ == "__main__":

    # Setup Basic logging cofiguration in case anything goes wrong during setup
    script_setup.setup_initial_logging()

    # Find the modified files by patch commit
    szz.find_modified_files()