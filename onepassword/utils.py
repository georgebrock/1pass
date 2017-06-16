import sys


def is_python_3():
    return sys.version.split(" ")[0].split(".")[0] =="3"
