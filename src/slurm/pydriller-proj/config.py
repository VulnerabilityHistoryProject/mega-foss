import logging


logger = logging.getLogger(__name__)

# Define global variables in a controlled way
class GlobalConfig:
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

logger.info("GlobalConfig initialized.")
