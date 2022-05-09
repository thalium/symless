import logging

import symless.settings as settings

logger = None


def print_delay(prefix: str, start: float, end: float):
    delay = int(end - start)
    min = int(delay / 60)
    sec = delay - (min * 60)
    logger.info(
        "%s in %s%s" % (prefix, "%d minutes and " % min if min > 0 else "", "%d seconds" % sec)
    )


"""
CRITICAL 50
ERROR 40
WARNING 30
INFO 20
DEBUG 10
NOTSET 0
"""


def set_logger():
    global logger
    # create logger
    logger = logging.getLogger("symless")

    # remove old handlers when there is a force reload of the imported module of the plugin
    if len(logger.handlers):
        for ch in logger.handlers:
            logger.removeHandler(ch)
    logger.setLevel(settings.settings.get_log_level())
    logger.propagate = False

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(settings.settings.get_log_level())

    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)s - %(funcName)20s() - %(message)s"
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger


logger = set_logger()
