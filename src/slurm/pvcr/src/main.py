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

    processed_cve: dict[str,cve_config.CVE]

    cve_data: Generator = stream_json_entries(json_file_path)

    for cve_entry in cve_data:

        json_cve_id: str = handle.safe_dict_get(cve_entry,"cve_id")
        partial_repo_path: str = handle.safe_dict_get(cve_entry,"repo")
        hash_patch_commit: str = handle.safe_dict_get(cve_entry,"commit")

        if json_cve_id not in processed_cve:

            # Create a new instance of the cve class
            cve_vuln: cve_config.CVE = cve_config.CVE(json_cve_id,partial_repo_path,hash_patch_commit)
            handle.safe_dict_set(processed_cve,json_cve_id,cve_vuln)

            return cve_vuln
        else: # what happens if the cve id is already in the set
            # don't create a new cve object, rather add the hash patch commit to the list from the patch commits class
            # CVE class should have a list 

            cve_vuln = handle.safe_dict_get(processed_cve,json_cve_id)
            cve_vuln.

            



if __name__ == "__main__":

    # Setup Basic logging cofiguration in case anything goes wrong during setup
    script_setup.setup_initial_logging()

    # Find the modified files by patch commit
    szz.find_modified_files()