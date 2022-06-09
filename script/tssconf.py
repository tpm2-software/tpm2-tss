#!/usr/bin/env python3

import argparse
import contextlib
import os
import re
import subprocess
import sys
import yaml


@contextlib.contextmanager
def smart_open(filename=None):
    if filename and filename != "-":
        fh = open(filename, "w")
    else:
        fh = sys.stdout

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()


def parse_yaml(path, function_to_file_map):

    with open(path, "r") as f:
        y = yaml.safe_load(f)

    if not isinstance(y, list):
        raise RuntimeError(f"Expected YAML file to be simple list, got: {type(y)}")

    unknown = set(y) - set(function_to_file_map.keys())
    if len(unknown) > 0:
        raise RuntimeError(f"Unknown functions, got: {unknown}")

    return y


def is_final_leaf(function):
    return function.startswith("Tss2_MU")


def do_we_care(function_name):

    cares = [r"Tss2_Sys.*", r"Esys_.*", r"Tss2_MU_.*"]

    for c in cares:
        if re.match(c, function_name):
            return True

    return False


def build_global_map(search_root):

    file_to_functions = {}
    function_to_file = {}
    #
    # We only look through sys and esapi, as MU is always a leaf function we can ignore it.
    # we also skip FAPI as we don't care about trimming it down, and we skip tcti stuffs as that
    # can be configured independently
    #
    cflow_output = subprocess.check_output(
        f'find {os.path.join(search_root, "tss2-sys")} {os.path.join(search_root, "tss2-esys")} -name \'*\.[c|h]\' -not -path \'*tss2-tcti*\' | xargs ctags -x --c-kinds=f',
        shell=True,
        stderr=subprocess.DEVNULL,
    )

    # make it a string
    cflow_output = cflow_output.decode()

    # These are all level 0 or definitions of functions, build a map to filename
    for l in cflow_output.splitlines():
        # Tss2_Sys_ZGen_2Phase function    115 /home/wcrobert/workspace/tpm2-tss/src/tss2-sys/api/Tss2_Sys_ZGen_2Phase.c TSS2_RC Tss2_Sys_ZGen_2Phase(
        chunks = l.split()

        function_name = chunks[0]
        file_name = chunks[3]

        if not do_we_care(function_name):
            continue

        # add to the function name to file name mapping
        if function_name in function_to_file:
            raise RuntimeError(f"Duplicate key {function_name}")
        function_to_file[function_name] = file_name

        # add to the file_name to function mapping
        if file_name not in file_to_functions:
            file_to_functions[file_name] = []
        file_to_functions[file_name].append(function_name)

    return file_to_functions, function_to_file


def cflow_output_to_callees(cflow_output, func):

    l = []

    for value in cflow_output.stdout.decode().splitlines():

        stripped_line = value.lstrip()
        # depth is indicated by indentation in 4 spaces
        depth = (len(value) - len(stripped_line)) // 4
        if depth == 0:
            current_function = stripped_line.split("(")[0]
            if func != current_function:
                current_function = None
                continue
        elif current_function is not None:
            # filter out callees we don't care about
            calls_function = value.strip().split("(")[0]
            if do_we_care(calls_function):
                l.append(calls_function)

    return l


def get_all_called_functions(func, functions_to_file):

    all_functions = []

    def add_called_functions(func):

        try:
            file_containing_func = functions_to_file[func]
        except KeyError as e:
            if is_final_leaf(func):
                all_functions.append(func)
                return []
            raise e
        cflow_output = subprocess.run(
            ["cflow", file_containing_func],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        #
        # returns:
        # foo:
        #  - baz
        #  - boo
        #
        callees = cflow_output_to_callees(cflow_output, func=func)
        all_functions.extend(callees)
        return callees

    def add_all_callees(func):
        callees_added = add_called_functions(func)

        # else start populating callee callees
        for callee in callees_added:
            add_all_callees(callee)

        return all_functions

    # start the recursion
    return add_all_callees(func)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser("TSS2 Configurator")
    argparser.add_argument(
        "--source-root",
        default=os.path.join(os.getcwd(), "src"),
        help="git source root directory (src), defaults to ${cwd}/src.",
    )
    argparser.add_argument("config", help="yaml config file")
    argparser.add_argument("--output", default=None, help="output file for defines")
    argparser.add_argument(
        "--debug", action="store_true", default=False, help="Enable debug output"
    )

    args = argparser.parse_args()

    # start by building a map of every defined function and it's filename
    file_to_functions, function_to_file = build_global_map(args.source_root)

    enabled_functions = parse_yaml(args.config, function_to_file)

    # for each function to enable, go find it's leafs
    all_callees = set()
    for func in enabled_functions:
        called_functions = set(get_all_called_functions(func, function_to_file))

        # debug output
        if args.debug:
            print(f"{func}:")
            for c in called_functions:
                print(f"  -{c}")

        # union in the new callees to prevent dups
        all_callees |= called_functions

    with smart_open(args.output) as f:
        # dump autogenerated warning and the ifdef prelude
        print("/* AUTOGENERATED FILE DO NOT MODIFY */\n", file=f)
        print("#ifndef CONFIGURATOR_H_\n#define CONFIGURATOR_H_", file=f)

        esys_enabled = False

        # add enabled functions
        for e in enabled_functions:
            if e.startswith("Esys"):
                esys_enabled = True
            print(f"#define ENABLE_{e.upper()} 1", file=f)

        # add callee defines
        for c in all_callees:
            print(f"#define ENABLE_{c.upper()} 1", file=f)

        # if ESYS is enabled.... enable sys init and ensure Esys_Initialize in there
        if esys_enabled:
            if (
                "Tss2_Sys_Initialize" not in enabled_functions
                or "Tss2_Sys_Initialize" not in all_callees
            ):
                add_fn = "Tss2_Sys_Initialize"
                print(f"#define ENABLE_{add_fn.upper()} 1", file=f)

            if (
                "Esys_Initialize" not in enabled_functions
                or "Esys_Initialize" not in all_callees
            ):
                add_fn = "Esys_Initialize"
                print(f"#define ENABLE_{add_fn.upper()} 1", file=f)

        # sys always needs
        always_needs = [
            "Tss2_Sys_Execute",
            "Tss2_Sys_ExecuteAsync",
            "Tss2_Sys_ExecuteFinish",
            "Tss2_Sys_GetRspAuths",
            "Tss2_Sys_SetCmdAuths",
        ]
        for a in always_needs:
            if a not in enabled_functions and a not in all_callees:
                print(f"#define ENABLE_{a.upper()} 1", file=f)

        # end prelude ifdef
        print("#endif", file=f)
