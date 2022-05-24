#!/usr/bin/python3

import inspect
import os
import shutil
import sys

"""
    Installs the symless plugin into your IDA plugins user directory :
    On Windows: %APPDATA%/Hex-Rays/IDA Pro
    On Linux and Mac: $HOME/.idapro


    Install: $ python3 install.py
    Uninstall: $ python3 install.py -u
"""

to_copy = [("symless_plugin.py", False), ("../symless", True)]

file_path = inspect.getsourcefile(lambda: 0)
root_dir = os.path.dirname(os.path.abspath(file_path))


def usage():
    print(f"Usage: python {sys.argv[0]} [-u] [-dev]")
    print("-u => uninstall plugin")
    print(
        "-dev => install plugin with symlinks in order to keep synchronised\
             the git folder and the plugin folder"
    )


if __name__ == "__main__":
    if os.name == "posix":
        ida_plugins_dir = os.path.expandvars("/$HOME/.idapro/plugins")
    elif os.name == "nt":
        ida_plugins_dir = os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/plugins")
    else:
        print("unknown os", os.name)

    # If its the first plugin to be installed

    os.makedirs(ida_plugins_dir, exist_ok=True)

    install = True
    symlink = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "-u":
            install = False
        elif sys.argv[1] == "-dev":
            symlink = True
        else:
            usage()
            sys.exit(1)

    if install and os.path.exists(os.path.join(ida_plugins_dir, "symless")):
        print("Symless is already present. Please uninstall before if you want to update")
        print("Aborting installation")
        exit()

    if install:
        print("Symless will be installed from %s directory" % ida_plugins_dir)
        if symlink:
            print("using symlink")
    else:
        print("Symless will be removed from %s directory" % ida_plugins_dir)

    for file, is_dir in to_copy:
        src = os.path.abspath(os.path.join(root_dir, file))
        dst = os.path.abspath(os.path.join(ida_plugins_dir, os.path.basename(file)))

        if install:
            if symlink:
                os.symlink(src, dst)
            else:
                if is_dir:
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy(src, dst)

        else:
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst)
            elif os.path.exists(dst):
                os.unlink(dst)


if install:
    print("Installation complete !")
else:
    print("Uninstallation complete !")
