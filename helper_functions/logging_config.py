import logging
import os
from datetime import datetime, timezone

LOG_LEVEL = logging.DEBUG


# Custom Formatter class to use ISO8601 format with UTC timezone
class ISO8601UTCFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.now(timezone.utc).isoformat()


# Custom Handling class based on FlushingFileHandler
# This helps to ensure that log messages are written to the file immediately
class FlushingFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logger(
    name: str,
    log_file: str,
    log_directory: str = "logs",
    level: str = LOG_LEVEL,
) -> logging.Logger:
    """Function to set up a logger with the specified name, log file, and level.
    Levels are as follows:
    - logging.DEBUG: Detailed information, typically of interest only when diagnosing problems.
    - logging.INFO: Confirmation that things are working as expected.
    - logging.WARNING: An indication that something unexpected happened, or indicative of some problem in the near future.
    - logging.ERROR: Due to a more serious problem, the software has not been able to perform some function.
    - logging.CRITICAL: A serious error, indicating that the program itself may be unable to continue running.

    Args:
        name: The name of the logger
        log_file: The name of the log file
        log_directory: The directory where the log file is stored
        level: The logging level (default: follows LOG_LEVEL constant)

    Returns:
        logger: The logger object
    """
    # Create the log directory if it does not exist
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    # Join the log directory and log file to get the full path
    log_file_full_path = os.path.join(log_directory, log_file)

    # Create a logger with the given name
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create a formatter that ensures each log message appears on its own line
    formatter = ISO8601UTCFormatter(
        "%(asctime)s\n%(name)s\n%(funcName)s\n%(levelname)s\n%(message)s\n"
    )

    # Use the custom handler
    custom_handler = FlushingFileHandler(log_file_full_path)
    custom_handler.setLevel(level)
    custom_handler.setFormatter(formatter)

    if not logger.hasHandlers():
        logger.addHandler(custom_handler)

    return logger