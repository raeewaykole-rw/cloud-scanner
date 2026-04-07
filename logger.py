"""Logger setup helpers."""

import logging


def setup_logger(level: int = logging.INFO) -> logging.Logger:
    """Create and configure a simple logger."""
    logger = logging.getLogger("cloud_scanner")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
