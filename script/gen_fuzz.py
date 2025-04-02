#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import os
import argparse
import itertools

# Makefile-fuzz-generated.am is created from this template.
MAKEFILE_FUZZ = """# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2018 Intel Corporation
# All rights reserved.

if ENABLE_TCTI_FUZZING
TESTS_FUZZ = %s
%s
endif # ENABLE_TCTI_FUZZING
"""
# Each fuzz target in Makefile-fuzz-generated.am is created from this template.
MAKEFILE_FUZZ_TARGET = """
noinst_PROGRAMS += test/fuzz/%s.fuzz
test_fuzz_%s_fuzz_CFLAGS  = $(TESTS_CFLAGS)
test_fuzz_%s_fuzz_LDFLAGS = $(TESTS_LDFLAGS)
test_fuzz_%s_fuzz_LDADD   = $(TESTS_LDADD)
nodist_test_fuzz_%s_fuzz_SOURCES  = test/fuzz/main-sys.c \\
        test/fuzz/%s.fuzz.c

DISTCLEANFILES += test/fuzz/%s.fuzz.c"""
# Common include definitions needed for fuzzing an SYS call
SYS_TEMPLATE = """/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <stdarg.h>

#include <setjmp.h>

#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_tcti_device.h"

#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-device.h"

#define LOGMODULE fuzz
#include "tss2_tcti.h"
#include "util/log.h"
#include "test.h"
#include "tss2-sys/sysapi_util.h"
#include "tcti/tcti-fuzzing.h"

int
test_invoke (
        TSS2_SYS_CONTEXT *sysContext)
{
    %s

    fuzz_fill (
        sysContext,
        %d,
        %s
    );

    %s (
        sysContext,
        %s
    );

    return EXIT_SUCCESS;
}
"""


def gen_file(function):
    """
    Generate a c file used as the fuzz target given the function definition
    from a header file.
    """
    # Parse the function name from the function definition
    function_name = (
        function.split("\n")[0].replace("TSS2_RC", "").replace("(", "").strip()
    )
    # Parse the function arguments into an array. Do not include sysContext.
    args = [
        arg.strip()
        for arg in function[function.index("(") + 1 : function.index(");")].split(",")
        if "TSS2_SYS_CONTEXT" not in arg
    ]
    return gen_target(function, function_name, args)


def gen_target(function, function_name, args):
    """
    Generate the c fuzz target for a SYS call
    """
    if not args:
        return function_name, None

    def get_name(arg):
        return arg.replace("*", "").split()[-1]
    def get_name_ptr(arg):
        return arg.replace("*", "").split()[-1] + "_ptr"
    def get_type(arg):
        return " ".join(arg.replace("*", " * ").split()[0:-1])
    def get_type_no_ptr(arg):
        return get_type(arg).replace("*", "").strip()
    def get_type_no_ptr_pointerized(arg):
        return get_type_no_ptr(arg) + " *"
    def get_name_maybe_ptr(arg):
        if is_ptr(arg):
            return get_name(arg) + "_ptr"
        return get_name(arg)
    def is_ptr(arg):
        return "*" in arg
    def get_definition(arg):
        definition = f"{get_type_no_ptr(arg)} {get_name(arg)} = {{0}};"
        # Add a variable which is a pointer to the above
        definition += f"\n    {get_type_no_ptr_pointerized(arg)} {get_name_ptr(arg)} = &{get_name(arg)};"
        return definition

    # Generate the c variable definitions. Make sure to initialize to empty
    # structs (works for initializing anything) or c compiler will complain.
    arg_definitions = ("\n" + " " * 4).join(
        get_definition(args) for args in args
    )
    # Generate the c arguments. For arguments that are pointers find replace *
    # with & so that we pass a pointer to the definition which has been
    # allocated on the stack.
    arg_call = (",\n" + " " * 8).join(
        [get_name_maybe_ptr(arg) for arg in args]
    )
    # Generate the call to fuzz_fill. The call should be the sysContext, double
    # the number of arguments for the _Prepare call, and then for each _Prepare
    # argument pass two to fuzz_fill, the sizeof the _Prepare argument, and a
    # pointer to it.
    fill_fuzz_args = (",\n" + " " * 8).join(
        [
            f"sizeof ({get_name(arg)}), &{get_name_ptr(arg)}, {str('*' in arg).lower()}"
            for arg in args
        ]
    )
    # Fill in the template
    return (
        function_name,
        SYS_TEMPLATE
        % (arg_definitions, len(args) * 3, fill_fuzz_args, function_name, arg_call),
    )


def functions_from_include(header):
    """
    Parse out and yield each function definition from a header file.
    """
    with open(header, "r") as header_fd:
        current_function = ""
        for line in header_fd:
            # Functions we are interested in start with Tss2_Sys_
            if "Tss2_Sys_" in line and "(" in line:
                # Set the current_function to this line
                current_function = line

                # Skip function if it
                # a) does not take a sys context (e.g. Tss2_Sys_GetContextSize)
                # b) messes with the sys context (e.g. Tss2_Sys_Finalize)
                # c) needs caller-allocated memory (e.g. Tss2_Sys_GetTctiContext)
                if (
                    "Tss2_Sys_GetContextSize" in current_function or
                    "Tss2_Sys_Initialize" in current_function or
                    "Tss2_Sys_Finalize" in current_function or
                    "Tss2_Sys_GetTctiContext" in current_function or
                    "Tss2_Sys_GetDecryptParam" in current_function or
                    "Tss2_Sys_GetCpBuffer" in current_function or
                    "Tss2_Sys_GetEncryptParam" in current_function or
                    "Tss2_Sys_GetRpBuffer" in current_function
                ):
                    current_function = ""
                    continue
            elif current_function and ");" in line:
                # When we reach the closing parenthesis yield the function
                yield current_function + line.rstrip()
                current_function = ""
            elif current_function:
                # Add all the arguments to the function
                current_function += line


def gen_files(header):
    # Generate a fuzz target c file from each function in the header file
    for current_function in functions_from_include(header):
        function_name, contents = gen_file(current_function)
        # Skip the yield if there is no fuzz target that can be generated
        if contents is None:
            continue
        # Yield the function name and the contents of its generated file
        yield function_name, contents


def main():
    parser = argparse.ArgumentParser(description="Generate libfuzzer for sys")
    parser.add_argument(
        "--header",
        default="include/tss2/tss2_sys.h",
        help="Header file to look in (default include/tss2/tss2_sys.h)",
    )
    args = parser.parse_args()

    functions = dict(gen_files(args.header))
    # Write the generated target to the file for its function name
    for function_name, contents in functions.items():
        filepath = os.path.join("test", "fuzz", function_name + ".fuzz.c")
        with open(filepath, "w") as fuzzer_fd:
            fuzzer_fd.write(contents)
    # Fill in the Makefile-fuzz-generated.am template using the function names.
    # Create a list of the compiled fuzz targets
    files = " \\\n    ".join(
        ["test/fuzz/%s.fuzz" % (function) for function in functions]
    )
    # Create the Makefile targets for each generated file
    targets = "\n".join(
        [
            MAKEFILE_FUZZ_TARGET % tuple(list(itertools.chain(([function] * 7))))
            for function in functions
        ]
    )
    # Write out the Makefile-fuzz-generated.am file
    with open("Makefile-fuzz-generated.am", "w") as makefile_fd:
        makefile_fd.write(MAKEFILE_FUZZ % (files, targets))


if __name__ == "__main__":
    main()
