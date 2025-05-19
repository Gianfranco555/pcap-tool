import logging
import sys
import json


def get_logger(name: str = __name__) -> logging.Logger:
    """Return a JSON-configured logger.

    Reuses existing handlers to avoid duplicates when called multiple times.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    fmt = json.dumps(
        {
            "ts": "%(asctime)s",
            "lvl": "%(levelname)s",
            "mod": "%(name)s",
            "msg": "%(message)s",
        }
    )
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
