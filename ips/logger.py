# ips/logger.py

import logging

# ANSI escape codes for colors
class Color:
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

class ColoredFormatter(logging.Formatter):
    """A logging formatter that adds color to log levels."""

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.INFO: Color.GREY + self.fmt + Color.RESET,
            logging.WARNING: Color.YELLOW + self.fmt + Color.RESET,
            logging.ERROR: Color.RED + self.fmt + Color.RESET,
            logging.CRITICAL: Color.BOLD_RED + self.fmt + Color.RESET,
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logger():
    """Sets up the global logger with our colored formatter."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers to avoid duplicate logs if the script is re-run
    if logger.hasHandlers():
        logger.handlers.clear()
        
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter('%(levelname)s: %(message)s'))
    logger.addHandler(handler)