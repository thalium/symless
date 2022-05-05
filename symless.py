#!/usr/bin/python3

import argparse
import inspect
import os
import sys
import time

file_path = inspect.getsourcefile(lambda: 0)
root_dir = os.path.dirname(os.path.abspath(file_path))


""" IDA main """


def print_delay(prefix: str, start: float, end: float):
    delay = int(end - start)
    min = int(delay / 60)
    sec = delay - (min * 60)
    print("%s in %s%s" % (prefix, "%d minutes and " % min if min > 0 else "", "%d seconds" % sec))


def ida_main():
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, help="config file")
    parser.add_argument("--prefix", type=str, default="", help="log prefix")
    args = parser.parse_args(idc.ARGV[1:])

    # check binary type
    if not arch.is_arch_supported():
        print("Error: Unsupported arch (%s) or filetype" % arch.get_proc_name())
        idc.qexit(0)

    # initial ida autoanalysis
    start = time.time()
    idaapi.auto_wait()
    print_delay("Info: initial IDA autoanalysis", start, time.time())

    # generate model
    start = time.time()
    model_context = model.generate_model(args.config)
    print_delay("Info: model generation done", start, time.time())

    if model_context is not None:

        # solve conflicts in the model
        start = time.time()
        conflict.solve_conflicts(model_context)
        print_delay("Info: conflicts solved", start, time.time())

        # get info from potential symbols
        symbols.name_structures(model_context)

        # import data in ida
        start = time.time()
        total = generation.generate_structs(model_context)
        print_delay("Info: ida database updated", start, time.time())

        # finalize operations
        start = time.time()
        idaapi.auto_wait()
        print_delay("Info: final IDA autoanalysis", start, time.time())

        print("Info: %d structures generated" % total)

    idc.qexit(0)


""" Command line main """


def cmd_usage():
    print(f"Usage: python {sys.argv[0]} [-c config.csv] <file(s)>")


def cmd_main():
    files = []
    config_path = os.path.abspath(os.path.join(root_dir, "symless", "config", "imports.csv"))

    # parse arguments
    i, length = 1, len(sys.argv)
    while i < length:
        if sys.argv[i] == "-c":
            i += 1
            if i == length:
                cmd_usage()
                return
            config_path = sys.argv[i]
        else:
            files.append(sys.argv[i])
        i += 1

    if len(files) == 0:
        cmd_usage()
        return

    args = ["--config", config_path]

    runner = os.path.abspath(os.path.join(root_dir, "symless.py"))
    for file in files:
        run_script(runner, os.path.abspath(file), args)


""" Symless main """

if __name__ == "__main__":
    try:
        # flake8: noqa: F401
        import ida_ida
        import idaapi
        import idc

    except ModuleNotFoundError:
        from run_script import run_script

        cmd_main()  # script run from command line

    else:
        import symless.conflict as conflict
        import symless.cpustate.arch as arch
        import symless.generation as generation
        import symless.model as model
        import symless.symbols as symbols

        ida_main()  # script run from IDA
