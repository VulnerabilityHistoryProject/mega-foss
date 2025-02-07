import logging

import error_handling as handle

logger = logging.getLogger(__name__)

class SCRIPT_CONFIG:
    logger = logging.getLogger(__name__)

    def __init__(self):
        # Call the class method to load environment variables
        self._initialize_environment_variables()

    @classmethod
    def _initialize_environment_variables(cls):
        variables_to_check = [
            "GIT_ALL_REPOS_DIR", 
            "PATCH_COMMITS_JSON", 
            "OUTPUT_DIR_JSON", 
            "LOGGING_DIR"
        ]
        handle.safe_get_env_vars(
            cls,
            variables_to_check,
            handle.MissingEnvironmentVariableError
        )

class CVE:
    def __init__(self):
        """Initialize an instance of CVE with default empty values."""
        self._cve_id: str = ""
        self._path_selected_repo: str = ""
        self._hash_patch_commit: str = ""
        self._hash_vuln_commit: str = ""
        self._mod_files_by_patch: set = set()
        self._mod_files_by_vuln_commit: set = set()
        self._changes_patch_commit: dict = {}
        self._changes_vuln_commit: dict = {}

    @property
    def cve_id(self) -> str:
        return self._cve_id

    @cve_id.setter
    def cve_id(self, value: str) -> None:
        self._cve_id = value

    @property
    def path_selected_repo(self) -> str:
        return self._path_selected_repo

    @path_selected_repo.setter
    def path_selected_repo(self, value: str) -> None:
        self._path_selected_repo = value

    @property
    def hash_patch_commit(self) -> str:
        return self._hash_patch_commit

    @hash_patch_commit.setter
    def hash_patch_commit(self, value: str) -> None:
        self._hash_patch_commit = value

    @property
    def hash_vuln_commit(self) -> str:
        return self._hash_vuln_commit

    @hash_vuln_commit.setter
    def hash_vuln_commit(self, value: str) -> None:
        self._hash_vuln_commit = value

    @property
    def mod_files_by_patch(self) -> set:
        return self._mod_files_by_patch

    @mod_files_by_patch.setter
    def mod_files_by_patch(self, value: set) -> None:
        self._mod_files_by_patch = value

    @property
    def mod_files_by_vuln_commit(self) -> set:
        return self._mod_files_by_vuln_commit

    @mod_files_by_vuln_commit.setter
    def mod_files_by_vuln_commit(self, value: set) -> None:
        self._mod_files_by_vuln_commit = value

    @property
    def changes_patch_commit(self) -> dict:
        return self._changes_patch_commit

    @changes_patch_commit.setter
    def changes_patch_commit(self, value: dict) -> None:
        self._changes_patch_commit = value

    @property
    def changes_vuln_commit(self) -> dict:
        return self._changes_vuln_commit

    @changes_vuln_commit.setter
    def changes_vuln_commit(self, value: dict) -> None:
        self._changes_vuln_commit = value

    
class CVE:
    CVE_ID: str = ""
    PATH_SELECTED_REPO: str = ""
    HASH_PATCH_COMMIT: str = ""
    HASH_VULN_COMMIT: str = ""
    MOD_FILES_BY_PATCH: set = set()
    MOD_FILES_BY_VULN_COMMIT: set = set()
    CHANGES_PATCH_COMMIT: dict = {}
    CHANGES_VULN_COMMIT: dict = {}

    @classmethod
    def initialize(cls):
        """Initialize missing global variables with default values."""
        for attr, default in cls.__dict__.items():
            if not attr.startswith("__") and getattr(cls, attr) in (None, ""):
                logger.error(f"Global variable '{attr}' is not initialized. Initializing it.")
                setattr(cls, attr, default)

        logger.info("CVE config initialized.")

    @classmethod
    

