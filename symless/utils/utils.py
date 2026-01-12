import logging
import os

import symless
import symless.config as config


def get_logger(level: int = config.g_settings.log_level):
    logger = logging.getLogger("symless")
    logger.setLevel(level)
    logger.propagate = False

    # do not recreate handler when reloading utils module
    if logger.hasHandlers():
        return logger

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(level)

    # log format
    formatter = logging.Formatter(
        "{asctime} - {name} - {levelname:<8s} {filename:>15s}:{lineno:05} - {funcName:<30s} - {message}",
        style="{",
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger


# initialize global logger
g_logger = get_logger()


# where to look for resources
def get_resources_path() -> str:
    return os.path.join(symless.__path__[0], "resources")


# print completed action & time it took
def print_delay(prefix: str, start: float, end: float):
    delay = int(end - start)
    min = int(delay / 60)
    sec = delay - (min * 60)
    g_logger.info("%s in %s%s" % (prefix, "%d minutes and " % min if min > 0 else "", "%d seconds" % sec))


# convert integer to given sign & size
def to_c_integer(value: int, sizeof: int, signed: bool = True) -> int:
    mask = 1 << (sizeof * 8)
    out = value & (mask - 1)
    if signed and (out & (mask >> 1)):
        out -= mask
    return out
