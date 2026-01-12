import argparse
import inspect
import os
import sys

import idaapi
import idc

# add symless dir to search path
symless_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0))), ".."))
sys.path.append(symless_dir)

import symless.utils.ida_utils as ida_utils
import symless.utils.vtables as vtables

""" Debug script - Scans binary for vtables """

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=str, default="")
    args = parser.parse_args(idc.ARGV[1:])

    idaapi.auto_wait()

    stats = [0, 0]

    for vtbl in vtables.get_all_vtables():
        name = ida_utils.demangle_ea(vtbl.ea)
        print("%s0x%x (size: 0x%x) -> %s" % (args.prefix, vtbl.ea, vtbl.size(), name))

        for x in vtbl.get_loads():
            print("%s\tload @ 0x%x" % (args.prefix, x))

        stats[1] += 1
        stats[0] += 1 if "vftable" in name else 0

    print("%sTotal: %d, corrects (from symbols): %d" % (args.prefix, stats[1], stats[0]))

idc.qexit(0)
