"""Utility helpers for the QR Phishing Detection System.

* Logging wrappers (simple console logger – can be swapped for any logging lib).
* Validation helpers used by the scanner and analyzer.
"""

import logging
from typing import Any

# Configure a basic logger – in a real project this could be extended.
logger = logging.getLogger("qr_phishing")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def log_debug(msg: str, *args: Any, **kwargs: Any) -> None:
    """Log a debug message.
    """
    logger.debug(msg, *args, **kwargs)


def log_info(msg: str, *args: Any, **kwargs: Any) -> None:
    logger.info(msg, *args, **kwargs)


def log_warning(msg: str, *args: Any, **kwargs: Any) -> None:
    logger.warning(msg, *args, **kwargs)


def log_error(msg: str, *args: Any, **kwargs: Any) -> None:
    logger.error(msg, *args, **kwargs)
