#!/usr/bin/python3

import argparse
import inspect
import os
import sys

file_path = inspect.getsourcefile(lambda: 0)
root_dir = os.path.dirname(os.path.abspath(file_path))


""" IDA main """


def ida_main():
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, help="config file")
    parser.add_argument("--prefix", type=str, default="", help="log prefix")
    args = parser.parse_args(idc.ARGV[1:])
    symless_analyse(args.config)

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
        import idc

    except ModuleNotFoundError:
        from run_script import run_script

        cmd_main()  # script run from command line

    else:
        from symless.symless_action import symless_analyse

        ida_main()  # script run from IDA
