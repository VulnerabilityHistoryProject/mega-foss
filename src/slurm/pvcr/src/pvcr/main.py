
from error_handling import logger_config
from configuration import script_setup as setup
from cve_utils import cve
from szz_utils import szz
from error_handling import handle_errors as handle


import logging
import json
from typing import Any,Generator


basic_logger = logging.getLogger("basic_logger")
robust_logger = logging.getLogger("robust_logging")


def init_configuration() -> None:
    """
    Get the full ROOT directory

    """
    pass

def stream_json_entries(json_file_path: str) -> Generator[dict[str, str], None, None]:
    """Generator that yields each entry from a JSON list one by one."""
    with open(json_file_path, "r", encoding="utf-8") as f:
        data: list[dict[str, str]] = json.load(f)  # Explicitly defining type as a list of dictionaries
        for entry in data:
            yield entry  # Yielding each entry one by one


def process_JSON_CVE(json_file_path: str, config: setup.SCRIPT_CONFIG) -> dict[str,cve.CVE]:

    processed_cves: dict[str,cve.CVE]

    cve_data: Generator[dict[str,str], None, None] = stream_json_entries(json_file_path)

    for cve_entry in cve_data:

        json_cve_id: str = handle.safe_dict_get(cve_entry,"cve_id")
        partial_repo_path: str = handle.safe_dict_get(cve_entry,"repo")
        patch_commit_hash: str = handle.safe_dict_get(cve_entry,"commit")


        if json_cve_id not in processed_cves:

            # Create a new instance of the cve class
            cve_vuln: cve.CVE = cve.CVE(json_cve_id,partial_repo_path,patch_commit_hash, config) ### Dependency Injection here ###
            handle.safe_dict_set(processed_cves,json_cve_id,cve_vuln)

        else: # what happens if the cve id is already in the set
            # don't create a new cve object, rather add the hash patch commit to the list from the patch commits class
            # CVE class should have a list 

            # Safely get the CVE class object from the dictionary
            cve_vuln = handle.safe_dict_get(processed_cves,json_cve_id)

            # Add the patch commit hash to the list of patch commits inside of the CVE object
            cve_vuln.add_patch_commit_obj_to_CVE(
                                                cve_vuln.create_patch_commit_obj(patch_commit_hash))
    return processed_cves
#### Next step ### 
### Figure out how to extend the functionality of the existing Commit, Repository, and Modified file
### classes from pydriller library!



if __name__ == "__main__":

    ### Setup Basic Logging ###
    

    ### Singleton Config Instance ###
    CONFIG = setup.SCRIPT_CONFIG()
    ### Dependency Injection ### 
    CVE_dict: dict[cve.CVE] = process_JSON_CVE(CONFIG.get_PATCH_COMMITS_JSON_FILE(),CONFIG)


    # Setup Basic logging cofiguration in case anything goes wrong during setup
    logger_config.setup_initial_logging()

    # Find the modified files by patch commit
    #szz.find_modified_files()