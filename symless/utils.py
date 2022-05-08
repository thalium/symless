def print_delay(prefix: str, start: float, end: float):
    delay = int(end - start)
    min = int(delay / 60)
    sec = delay - (min * 60)
    print("%s in %s%s" % (prefix, "%d minutes and " % min if min > 0 else "", "%d seconds" % sec))
