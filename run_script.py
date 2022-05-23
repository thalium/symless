import os
import platform
import random
import string
import subprocess
import sys
import tempfile


def stderr_print(line: str):
    sys.stderr.write(line + "\n")


# remove quote from start & end of a path
# quotes can appear in env var when setting them from windows cmd
def unquote(path: str) -> str:
    if path[0] == '"' and path[-1] == '"':
        return path[1:-1]
    return path


# find idat executables
def find_idat() -> (str, str):
    ida_dir = None

    # user defined IDA path
    if "IDA_DIR" in os.environ.keys():
        ida_dir = os.path.abspath(unquote(os.environ["IDA_DIR"]))
    else:
        if sys.platform == "win32":
            base = R"C:\Program Files\IDA Pro 7."
        else:
            base = "%s/idapro-7." % os.environ["HOME"]

        for i in range(5, 8):
            current = "%s%d" % (base, i)
            if os.path.exists(current):
                ida_dir = current

    if ida_dir is None:
        stderr_print("Please specify an IDA installation location using IDA_DIR env")
        return None

    suffix = ".exe" if sys.platform == "win32" else ""
    ida32 = os.path.join(ida_dir, "idat" + suffix)
    ida64 = os.path.join(ida_dir, "idat64" + suffix)

    if not os.path.isfile(ida32):
        stderr_print('Missing idat%s in "%s"' % (suffix, ida_dir))
        return None

    if not os.path.isfile(ida64):
        stderr_print('Missing idat64%s in "%s"' % (suffix, ida_dir))
        return None

    return (ida32, ida64)


# craft IDA batch command
def craft_ida_command(idat: str, idb: str, script: str, script_args: [str]) -> (str, str):
    exec_name = os.path.basename(idb).split(".")[0]
    log_file = tempfile.mktemp(prefix=f"{exec_name}_", suffix=".log")

    if len(script_args) == 0:
        quoted_args = ""
    else:
        quoted_args = ' \\"' + '\\" \\"'.join(script_args) + '\\"'

    cmd = f'"{idat}" -A -L"{log_file}" -S"\\"{script}\\"{quoted_args}" "{idb}"'

    return (cmd, log_file)


# run ida -B filepath
def run_ida_batchmode(idat: str, filepath: str) -> int:
    args = f'"{idat}" -B "{filepath}"'
    process = subprocess.Popen(args, shell=(platform.system() != "Windows"))

    code = process.wait()
    if code != 0:
        return code

    # remove assembler file generated by analysis.idc
    os.remove(filepath + ".asm")

    return 0


# Create .idb from 32 bits executable or .i64 from 64 bits exe
def make_idb(ida_install: tuple, filepath: str) -> (str, int):
    if run_ida_batchmode(ida_install[0], filepath) == 0:
        return (f"{filepath}.idb", 0)

    # 32 bits analysis failed, try 64 bits mode
    code = run_ida_batchmode(ida_install[1], filepath)
    if code == 0:
        return (f"{filepath}.i64", 0)

    return (None, code)


# random string prefix to retrieve script output in IDA logs
def get_random_string(size: int) -> str:
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(size))


def is_idb(filename: str) -> bool:
    return filename.split(".")[-1] in ("i64", "idb")


def run_ida(ida_install: tuple, input_file: str, script: str, script_args: [str]) -> bool:
    if not is_idb(input_file):
        print("Creating IDA database from binary %s" % input_file)
        (idb_file, ret_code) = make_idb(ida_install, input_file)
        if ret_code != 0:
            stderr_print(f"Could not create initial database, IDA batchmode returned {ret_code}")
            return False
    else:
        idb_file = input_file

    # no script, just generate idb
    if len(script) == 0:
        return True

    prefix = get_random_string(6)
    script_args += ["--prefix", prefix]

    idat = ida_install[1] if idb_file.endswith(".i64") else ida_install[0]
    cmd, log_file = craft_ida_command(idat, idb_file, script, script_args)

    # TODO : Stderr is not deontological.. please find a solution
    # These logs need to not be present in the dump for the diff run during the test
    stderr_print("Running IDA script..")
    stderr_print("* IDAT  : %s" % idat)
    stderr_print(
        "* Script: %s%s"
        % (script, "" if len(script_args) == 0 else ' ("%s")' % '", "'.join(script_args))
    )
    stderr_print("* Base  : %s" % idb_file)
    stderr_print("* Logs  : %s" % log_file)

    process = subprocess.Popen(cmd, shell=(platform.system() != "Windows"))
    code = process.wait()

    try:
        output = open(log_file, "r")
    except FileNotFoundError:
        stderr_print("[-] IDA script did not produce logs, return code: %d" % code)
        return False

    if code == 0:
        stderr_print("IDA script terminated successfully.")

        line = True
        while line:

            line = output.readline()
            if not line.startswith(prefix):
                continue

            print(line.strip()[len(prefix) :])
    else:
        stderr_print("Trace:")
        stderr_print(output.read())
        stderr_print(f"[-] Status code:\t{hex(code)}")

    output.close()

    return code == 0


def run_script(script: str, input_file: str, args: [str] = None) -> int:
    ida_install = find_idat()
    if ida_install is None:
        return 1

    if args is None:
        args = []  # new args array, do not used the same default one between multiple calls

    return int(not run_ida(ida_install, input_file, script, args))


def usage():
    print("Usage: run_script.py <script.py> <input.i64> [args]")


def main() -> int:
    if len(sys.argv) < 3:
        usage()
        return 1

    return run_script(sys.argv[1], sys.argv[2], sys.argv[3:])


if __name__ == "__main__":
    exit(main())
