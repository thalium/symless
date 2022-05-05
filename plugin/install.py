#!/usr/bin/python3

import inspect
import os
import shutil
import sys

'''
    Installs the symless plugin into your IDA plugins,
    uses the IDA_DIR env to locate IDA installation    

    Install: $ python3 install.py
    Uninstall: $ python3 install.py -u
'''

to_copy = [("symless_plugin.py", False), ("../symless", True)]

file_path = inspect.getsourcefile(lambda: 0)
root_dir = os.path.dirname(os.path.abspath(file_path))


def usage():
    print(f"Usage: python {sys.argv[0]} [-u]")


if __name__ == "__main__":
    if "IDA_DIR" not in os.environ.keys():
        print("missing IDA_DIR environment variable")
        sys.exit(1)

    ida_dir = os.path.abspath(os.environ["IDA_DIR"])
    ida_plugins_dir = os.path.abspath(os.path.join(ida_dir, "plugins"))

    install = True
    if len(sys.argv) > 1:
        if sys.argv[1] == "-u":
            install = False
        else:
            usage()
            sys.exit(1)

    for file, is_dir in to_copy:
        src = os.path.abspath(os.path.join(root_dir, file))
        dst = os.path.abspath(os.path.join(ida_plugins_dir, os.path.basename(file)))

        if install:
            if is_dir:
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy(src, dst)
        else:
            if is_dir:
                shutil.rmtree(dst, ignore_errors = True)
            else:
                try:
                    os.unlink(dst)
                except FileNotFoundError:
                    pass