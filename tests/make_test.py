import os
import subprocess
import sys


def usage():
    print(
        "in order to run symless and dump information on all the binaries of the tests/bin/ folder :"
    )
    print("python make_test.py")
    print("in order to make a regression test")
    print("python make_test.py diff <commit to diff>")


usage()


def is_64bit_elf(filename):
    with open(filename, "rb") as f:
        c = f.read(5)
        return c[-1] == 2 and c[1:4] == b"ELF"


def is_32bit_elf(filename):
    with open(filename, "rb") as f:
        return f.read(4)[1:4] == b"ELF"


def is_64bit_pe(filename):
    with open(filename, "rb") as f:
        c = f.read()
        if b"\x50\x45\x00\x00\x64\x86" in c:
            return True
    return False


def is_32bit_pe(filename):
    with open(filename, "rb") as f:
        c = f.read()
        if b"\x50\x45\x00\x00\x4c\x01" in c:
            return True
    return False


def generate_makefile():

    bins = []
    for f in os.listdir("./bin"):
        fp = os.path.join("./bin", f)
        if not os.path.isfile(fp):
            print(fp, "is dir")
            continue
        if fp.endswith(".i64") or fp.endswith("idb"):
            print(fp, "is ida base")
            continue
        if is_64bit_elf(fp):
            print(fp, "is 64 bit elf")
            bins += [(f, "linux64", "out", 64)]
        elif is_32bit_elf(fp):
            print(fp, "is 32 bit elf")
            bins += [(f, "linux32", "out", 32)]
        elif is_32bit_pe(fp):
            print(fp, "is 32bit pe ")
            bins += [(f, "win32", "out", 32)]
        elif is_64bit_pe(fp):
            print(fp, "is 64bit pe ")
            bins += [(f, "win64", "out", 64)]
        else:

            print(fp, "is nothing")
            continue

    makefiles = ""

    for b in bins:
        bb = b[:-1][::-1]
        fp = os.path.join(*list(bb))
        os.makedirs(fp, exist_ok=True)
        print(b)

        makefile = f"""bitness={b[-1]}
target={b[0]}
include ../../../common.mk
"""
        print(makefile)
        bbb = bb + ("Makefile",)
        with open(os.path.join(*bbb), "w") as f:
            f.write(makefile)

        makefile = f""".PHONY: {b[0]}
{b[0]}:
\tcd ./{os.path.join(*bb)}; make clean; make apply; make dump

"""
        makefiles += makefile

    makefiles += ".PHONY: all\nall: "
    for b in bins:

        makefiles += "%s " % b[0]

    f = open("Makefile", "w")
    f.write(makefiles)
    f.close()

    return bins


def make():
    p = subprocess.Popen(["make", "all", "-j8"])
    p.wait()


def checkout(commit):
    p = subprocess.Popen(["git", "checkout", commit])
    p.wait()


def switch(branch):
    p = subprocess.Popen(["git", "switch", branch])
    p.wait()


def stash():
    p = subprocess.Popen(["git", "stash"])
    p.wait()


def stashpop():
    p = subprocess.Popen(["git", "stash", "pop"])
    p.wait()


def select_branches():
    if len(sys.argv) > 2:
        if sys.argv[1] == "diff":
            p = subprocess.Popen(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], stdout=subprocess.PIPE
            )
            orig_branch = p.stdout.read().strip()

            p = subprocess.Popen(["git", "rev-parse", "HEAD"], stdout=subprocess.PIPE)
            orig_commit = p.stdout.read().strip()

            diff_commit = sys.argv[2]
            return orig_branch, orig_commit, diff_commit
    return None, None, None


bins = generate_makefile()
orig_branch, orig_commit, diff_commit = select_branches()

if orig_branch is None:
    make()
    exit()

stash()
checkout(diff_commit)
make()
switch(orig_branch)
make()
stashpop()


for b in bins:
    bb = b[:-1][::-1]
    fp_orig = os.path.join(*list(bb), "dump", f"{b[0]}_{orig_commit.decode()}.dump")
    fp_diff = os.path.join(*list(bb), "dump", f"{b[0]}_{diff_commit}.dump")

    print("--------------------------------------------")
    print("--------------------------------------------")
    print("--------------------------------------------")
    print(b)
    print(" ".join(["diff", "--color", fp_diff, fp_orig]))
    print(" ".join(["code", "--diff", fp_diff, fp_orig]))
    print("--------------------------------------------")
    print("--------------------------------------------")
    print("--------------------------------------------")

    p = subprocess.Popen(["diff", "--color", fp_diff, fp_orig])
    p.wait()
    print()
    print()
    print()
