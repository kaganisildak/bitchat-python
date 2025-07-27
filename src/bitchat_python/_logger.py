import logging

__all__ = (
    "logger",
    "enable_file_logging",
)

logger = logging.getLogger("bitchat")
logger.setLevel(logging.WARNING)  # default log level

BASIC_FORMAT = "%(levelname)s:%(name)s:%(message)s"
# use on need
# BASIC_FORMAT_WITH_TIME = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# EXTENDED_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"

formatter = logging.Formatter(BASIC_FORMAT)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # handler's level should be lowest
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def enable_file_logging(logfile: str = "bitchat.log", mode: str = "a") -> None:
    """Helper to enable logging to a file."""
    file_handler = logging.FileHandler(logfile, mode, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # handler's level should be lowest
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
