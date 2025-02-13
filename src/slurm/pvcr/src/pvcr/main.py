
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


def process_JSON_CVE(json_file_path: str, config: setup.SCRIPT_CONFIG, cve_map: cve.PatchVulnBiMap) -> dict[str,cve.CVE]:


    cve_data: Generator[dict[str,str], None, None] = stream_json_entries(json_file_path)

    for cve_entry in cve_data:

        json_cve_id: str = handle.safe_dict_get(cve_entry,"cve_id")
        partial_repo_path: str = handle.safe_dict_get(cve_entry,"repo")
        patch_commit_hash: str = handle.safe_dict_get(cve_entry,"commit")


        if json_cve_id not in cve_map: ### Check if cve is already in the bi map ###

            # Create a new instance of the cve class
            cve_vuln: cve.CVE = cve.CVE(json_cve_id,partial_repo_path,patch_commit_hash, config,patch_vuln_bi_map=cve_map) ### Dependency Injection here ###
            
            ### Add primary patch commit to bi map if it hasn't been added yet ###
            cve_vuln.add_to_BiMap(cve_id=json_cve_id,patch_commit=cve_vuln._primary_patch_commit)

        else: # what happens if the cve id is already in the set
            

            '''
            There's a case where there are multiple patches (cves for a single vuln)
            '''

            # Want to create a new Patch commit object and add it to the bi map
            # How do I just create a new patch commit obejct
            

            # Get the cve value from the map (perform a lookup!)
            ## next --> create the get patch for cve id
            ## based on json_cve_id ... create a new Patch object and add it under

            '''
            issue... two patches have the same cve id, but they have different patch hashes and I don't have the vulnerability yet

            op 1) try and find the vuln in this function (that gonna take a sec)
            op 2) create an empty vuln object that I later add the details for once I find it THIS ONE I THINK
            '''
            cve_map.
           
    return 


#### Next step ### 
### Figure out how to extend the functionality of the existing Commit, Repository, and Modified file
### classes from pydriller library!

def export_cve_objects_as_json(processed_cves: dict[str,cve.CVE]) -> None:
    pass

def pickle_cve_objects(processed_cves: dict[str,cve.CVE]) -> None:
    """
    Pickle cve objects and store them in the data_sources/output_data/cve_pickle_objets directory

    Caution: For instance, if the class depends on a function from a different module, that module should be imported before unpickling.

    Args:
        processed_cves (dict[str,cve.CVE]): _description_
    """
    pass

if __name__ == "__main__":

    ### TO-DO ###
# make sure that when I call functions in error_handling, to use Pass or continue keyword to skip to the next thing
## ***** above is very important    
# copy all code over and adjust variable names and add necessary error handling for skipping messed up cases
# write code to get the previous commit (the one directly before the patch) this way we can compare that to the other hash.
# write code to get the specific path to the git repo of the selected FOSS Project for the specific patch commit from list in json. Fill PATH_SELECTED_REPO:str = "" variable 
# write code to get the vuln changes for CHANGES VULN COMMIT in the same format as the patch commit. Reusability!
# write code to get the parent directory with all the .git repos. Use error handling to make sure there is a .git file
# write code to get the name / directory of the FOSS project in the json and verify it exists in the parent directory with all .git repos.
# write code to write the original patch commit, directly prev commit, and the suspected vuln commit (or replace with error if unable to find), and changes to a new json file --> This is the solution
# write correct shebang at the top of script aka find location of python3 on RC
# put all paths into the .env file when I login to RC and find everything on my terminal. Can I carry the .env file with me??? How are env vars handled on RC?
# write code to write the commit changes to the json file (this is already kinda done, but I need to clean it up)
# add env variables to .env 
# go back through all setters in cve_config and write functions to actually get the data in the fields. Like for Vuln classifier. How do I get that info ?
# answer this question --> Where am I getting path selected repo, the repo that's selected for that particular iteration of for loop
## Create another file / section that focuses on analyzing the dataset once json data is processed that we have with python. Doesn't necessarily have to be 
## run in the script. It can be run after we get the data. Maybe make a jupyter notebook?
## create a recursive algorithm that traverses the modified files and changes in each commit object / vuln object commit in the bi map ???

    '''
    Question: do the people maintian pydriller well?? The docs seem kinda off no cap
    '''

    ### Setup Basic Logging ###
    basic_logger = logger_config.setup_initial_logging()

    ### Singleton Config Instance ###
    CONFIG = setup.SCRIPT_CONFIG(basic_logger)

    ### Singleton Bidirectional Map Instance ###
    CVE_MAP = cve.PatchVulnBiMap()

    ### Dependency Injection ### 
    CVE_dict: dict[cve.CVE] = process_JSON_CVE(CONFIG.get_PATCH_COMMITS_JSON_FILE(),CONFIG)
    

    # Find the modified files by patch commit
    #szz.find_modified_files()