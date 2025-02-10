
import os
import sys
import logging

import src.cve_utils.cve_config as config

from logging.handlers import RotatingFileHandler
from datetime import datetime

def setup_initial_logging() -> None:
    """
    This function will be called inside of main before calling subsequent functions.
    """
    # Basic logging setup for initialization phase
    log_file_path: str = 'setup_logs.txt'

    # Ensure the log file is in the same directory as the script
    log_dir: str = os.path.dirname(os.path.abspath(__file__))
    log_file: str = os.path.join(log_dir, log_file_path)

    # Set up file logging with rotation (in case the file grows large)
    logging.basicConfig(
        level=logging.DEBUG,  # Set the logging level to DEBUG
        format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
        handlers=[logging.FileHandler(log_file)]  # Only log to the file, no console output
    )

    # Get the logger
    logger: logging.Logger = logging.getLogger("basic_logger")

    # Example logging message
    logger.info("Basic logging setup complete.")


def setup_robust_logging(configs: config.SCRIPT_CONFIG, log_directory: str = "") -> None:
    """
    Set up logging to a file with rotation, using a specified directory.
    If no directory is provided, use the global PATH_LOG_OUTPUT_DIR.

    Args:
        log_directory (str, optional): Defaults to "" in preparation for assignment to global variable.
    """
    # Assuming a global logger object for logging
    logger = logging.getLogger("robust_logger")
    logger.setLevel(logging.DEBUG)

    
    
    # Check if log directory is provided or use default global variable
    if log_directory == "":
        log_directory = configs
    
    # If log directory is still not set, exit
    if not log_directory:
        logger.error("Log directory is not set. Cannot initialize logging.")
        sys.exit(1)

    # Ensure the log directory exists
    if not os.path.exists(log_directory):
        os.makedirs(log_directory, exist_ok=True)

    # Create a timestamped log file name
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file: str = f'error_log_{timestamp}.txt'
    log_path: str = os.path.join(log_directory, log_file)

    # Check if the log file exists, and if so, increment the name
    if os.path.exists(log_path):
        i = 2
        while os.path.exists(os.path.join(log_directory, f'error_log_{timestamp}_{i}.txt')):
            i += 1
        log_path = os.path.join(log_directory, f'error_log_{timestamp}_{i}.txt')

    # Set up rotating log file handler with max size of 5MB and 10 backup files
    handler: RotatingFileHandler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=10)
    handler.setLevel(logging.DEBUG)

    # Define log format: includes time, log level, message, and line number
    formatter: logging.Formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s - Line: %(lineno)d')
    handler.setFormatter(formatter)

    # Add the handler to the root logger (or any specific logger you prefer)
    logger.addHandler(handler)

    # Confirm that logging has been set up successfully
    logger.info("File-based logging has been set up successfully.")
