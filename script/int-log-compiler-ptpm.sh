#!/usr/bin/env bash
#;**********************************************************************;
# Copyright (c) 2017 - 2018, Intel Corporation
# Copyright (c) 2018 Fraunhofer SIT sponsored by Infineon Technologies AG
# All rights reserved.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;
set -u

usage_error ()
{
    echo "$0: $*" >&2
    print_usage >&2
    exit 2
}
print_usage ()
{
    cat <<END
Usage:
    int-log-compiler.sh --ptpm=DEVICE
                        TEST-SCRIPT [TEST-SCRIPT-ARGUMENTS]
The '--simulator-bin' option is mandatory.
END
}
while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
    -d|--ptpm) PTPM=$2; shift;;
    -d=*|--ptpm=*) PTPM="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# Verify the running shell and OS environment is sufficient to run these tests.
sanity_test ()
{
    # Check special file
    if [ ! -e /dev/urandom ]; then
        echo  "Missing file /dev/urandom; exiting"
        exit 1
    fi

    # Check ps
    PS_LINES=$(ps -e 2>/dev/null | wc -l)
    if [ "$PS_LINES" -eq 0 ] ; then
        echo "Command ps not listing processes; exiting"
        exit 1
    fi
}

sanity_test

# Once option processing is done, $@ should be the name of the test executable
# followed by all of the options passed to the test executable.
TEST_BIN=$(realpath "$1")
TEST_DIR=$(dirname "$1")
TEST_NAME=$(basename "${TEST_BIN}")

while true; do

env TPM20TEST_TCTI_NAME="device" \
    TPM20TEST_DEVICE_FILE=${PTPM} \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_transientempty
if [ $? -ne 0 ]; then
    echo "TPM transient area not empty => skipping"
    ret=77
    break
fi

echo "Execute the test script"
env TPM20TEST_TCTI_NAME="device" \
    TPM20TEST_DEVICE_FILE=${PTPM} \
    G_MESSAGES_DEBUG=all $@
ret=$?
echo "Script returned $ret"

env TPM20TEST_TCTI_NAME="device" \
    TPM20TEST_DEVICE_FILE=${PTPM} \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_transientempty
if [ $? -ne 0 ]; then
    echo "TPM transient area not empty or generally failed after test"
    ret=99
    break
fi

break
done

# This sleep is sadly necessary: If we kill the tabrmd w/o sleeping for a
# second after the test finishes the simulator will die too. Bug in the
# simulator?
sleep 1
# teardown
exit $ret
