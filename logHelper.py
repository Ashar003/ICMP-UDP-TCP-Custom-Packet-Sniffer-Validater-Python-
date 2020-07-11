import logging

def setup_logger(name, log_file, level=logging.ERROR):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger
