import script_setup
import cve_config
import szz
import error_handling as handle


import logging
import json

from typing import Any


logger = logging.getLogger(__name__)


def process_JSON_CVE(json_file_path: str) -> cve_config.CVE:
    with open(json_file_path, 'r') as file:
        cve_data: list[dict[str, Any]] = json.load(file)

    for cve_entry in cve_data:

        handle.safe_dict_set(cve_entry,)
        cve_id: str = cve_entry["cve_id"]
        repo: str = cve_entry["repo"]
        commit: str = cve_entry["commit"]

        handle.




if __name__ == "__main__":

    # Setup Basic logging cofiguration in case anything goes wrong during setup
    script_setup.setup_initial_logging()

    # Find the modified files by patch commit
    szz.find_modified_files()