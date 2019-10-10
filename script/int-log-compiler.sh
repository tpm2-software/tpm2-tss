#!/usr/bin/env bash
#;**********************************************************************;
# Copyright (c) 2017 - 2018, Intel Corporation
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
    int-log-compiler.sh TEST-SCRIPT [TEST-SCRIPT-ARGUMENTS]
END
}
while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
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

    if [ -z "$(which tpm_server)" ]; then
        echo "tpm_server not on PATH; exiting"
        exit 1
    fi

    if [ -z "$(which ss)" ]; then
        echo "ss not on PATH; exiting"
        exit 1
    fi
}

# This function takes a PID as a parameter and determines whether or not the
# process is currently running. If the daemon is running 0 is returned. Any
# other value indicates that the daemon isn't running.
daemon_status ()
{
    local pid=$1

    if [ $(kill -0 "${pid}" 2> /dev/null) ]; then
        echo "failed to detect running daemon with PID: ${pid}";
        return 1
    fi
    return 0
}

# This is a generic function to start a daemon, setup the environment
# variables, redirect output to a log file, store the PID of the daemon
# in a file and disconnect the daemon from the parent shell.
daemon_start ()
{
    local daemon_bin="$1"
    local daemon_opts="$2"
    local daemon_log_file="$3"
    local daemon_pid_file="$4"
    local daemon_env="$5"

    env ${daemon_env} stdbuf -o0 -e0 ${daemon_bin} ${daemon_opts} > ${daemon_log_file} 2>&1 &
    local ret=$?
    local pid=$!
    if [ ${ret} -ne 0 ]; then
        echo "failed to start daemon: \"${daemon_bin}\" with env: \"${daemon_env}\""
        exit ${ret}
    fi
    sleep 1
    daemon_status "${pid}"
    if [ $? -ne 0 ]; then
        echo "daemon died after successfully starting in background, check " \
             "log file: ${daemon_log_file}"
        return 1
    fi
    echo ${pid} > ${daemon_pid_file}
    disown ${pid}
    echo "successfully started daemon: ${daemon_bin} with PID: ${pid}"
    return 0
}
# function to start the simulator
# This also that we have a private place to store the NVChip file. Since we
# can't tell the simulator what to name this file we must generate a random
# directory under /tmp, move to this directory, start the simulator, then
# return to the old pwd.
simulator_start ()
{
    local sim_bin="$1"
    local sim_port="$2"
    local sim_log_file="$3"
    local sim_pid_file="$4"
    local sim_tmp_dir="$5"
    # simulator port is a random port between 1024 and 65535

    cd ${sim_tmp_dir}
    daemon_start "${sim_bin}" "-port ${sim_port}" "${sim_log_file}" \
        "${sim_pid_file}" ""
    local ret=$?
    cd -
    return $ret
}
# function to stop a running daemon
# This function takes a single parameter: a file containing the PID of the
# process to be killed. The PID is extracted and the daemon killed.
daemon_stop ()
{
    local pid_file=$1
    local pid=0
    local ret=0

    if [ ! -f ${pid_file} ]; then
        echo "failed to stop daemon, no pid file: ${pid_file}"
        return 1
    fi
    pid=$(cat ${pid_file})
    daemon_status "${pid}"
    ret=$?
    if [ ${ret} -ne 0 ]; then
        echo "failed to detect running daemon with PID: ${pid}";
        return ${ret}
    fi
    kill ${pid}
    ret=$?
    if [ ${ret} -ne 0 ]; then
        echo "failed to kill daemon process with PID: ${pid}"
    fi
    return ${ret}
}

sanity_test

# Once option processing is done, $@ should be the name of the test executable
# followed by all of the options passed to the test executable.
TEST_BIN=$(realpath "$1")
TEST_DIR=$(dirname "$1")
TEST_NAME=$(basename "${TEST_BIN}")

# start an instance of the simulator for the test, have it use a random port
SIM_LOG_FILE=${TEST_BIN}_simulator.log
SIM_PID_FILE=${TEST_BIN}_simulator.pid
SIM_TMP_DIR=$(mktemp --directory --tmpdir=/tmp tpm_server_XXXXXX)
PORT_MIN=1024
PORT_MAX=65534
BACKOFF_FACTOR=2
BACKOFF_MAX=6
BACKOFF=1
for i in $(seq ${BACKOFF_MAX}); do
    SIM_PORT_DATA=$(od -A n -N 2 -t u2 /dev/urandom | awk -v min=${PORT_MIN} -v max=${PORT_MAX} '{print ($1 % (max - min)) + min}')
    if [ $(expr ${SIM_PORT_DATA} % 2) -eq 1 ]; then
        SIM_PORT_DATA=$((${SIM_PORT_DATA}-1))
    fi
    SIM_PORT_CMD=$((${SIM_PORT_DATA}+1))
    echo "Starting simulator on port ${SIM_PORT_DATA}"
    simulator_start tpm_server ${SIM_PORT_DATA} ${SIM_LOG_FILE} ${SIM_PID_FILE} ${SIM_TMP_DIR}
    sleep 1 # give daemon time to bind to ports
    if [ ! -s ${SIM_PID_FILE} ] ; then
        echo "Simulator PID file is empty or missing. Giving up."
        exit 1
    fi
    PID=$(cat ${SIM_PID_FILE})
    echo "simulator PID: ${PID}";
    ss -lt4pn 2> /dev/null | grep "${PID}" | grep -q "${SIM_PORT_DATA}"
    ret_data=$?
    ss -lt4pn 2> /dev/null | grep "${PID}" | grep -q "${SIM_PORT_CMD}"
    ret_cmd=$?
    if [ \( $ret_data -eq 0 \) -a \( $ret_cmd -eq 0 \) ]; then
        echo "Simulator with PID ${PID} bound to port ${SIM_PORT_DATA} and " \
             "${SIM_PORT_CMD} successfully.";
        break
    fi
    echo "Port conflict? Cleaning up PID: ${PID}"
    kill "${PID}"
    BACKOFF=$((${BACKOFF}*${BACKOFF_FACTOR}))
    echo "Failed to start simulator: port ${SIM_PORT_DATA} or " \
         "${SIM_PORT_CMD} probably in use. Retrying in ${BACKOFF}."
    sleep ${BACKOFF}
    if [ $i -eq 10 ]; then
        echo "Failed to start simulator after $i tries. Giving up.";
        exit 1
    fi
done

while true; do

env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_startup
if [ $? -ne 0 ]; then
    echo "TPM_StartUp failed"
    ret=99
    break
fi

EKPUB_FILE=${TEST_BIN}_ekpub.pem
EKCERT_FILE=${TEST_BIN}_ekcert.crt
INTERMEDCA_FILE=${TEST_BIN}_intermed-ca.pem
ROOTCA_FILE=${TEST_BIN}_root-ca.pem

env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_getek>$EKPUB_FILE
if [ $? -ne 0 ]; then
    echo "TPM_getek failed"
    ret=99
    break
fi

EKECCPUB_FILE=${TEST_BIN}_ekeccpub.pem
EKECCCERT_FILE=${TEST_BIN}_ekecccert.crt
INTERMEDCA_FILE=${TEST_BIN}_intermedecc-ca.pem
ROOTCA_FILE=${TEST_BIN}_root-ca.pem

env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_getek_ecc>$EKECCPUB_FILE
if [ $? -ne 0 ]; then
    echo "TPM_getek_ecc failed"
    ret=99
    break
fi

SCRIPTDIR="$(dirname $(realpath $0))/"
${SCRIPTDIR}/ekca/create_ca.sh "${EKPUB_FILE}" "${EKECCPUB_FILE}" "${EKCERT_FILE}" \
                               "${EKECCCERT_FILE}" "${INTERMEDCA_FILE}" "${ROOTCA_FILE}" >${TEST_BIN}_ca.log 2>&1
if [ $? -ne 0 ]; then
    echo "ek-cert ca failed"
    ret=99
    break
fi

#hd $EKCERT_FILE
#openssl x509 -in $EKCERT_FILE -inform DER -text -noout

cat $EKCERT_FILE | \
env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_writeekcert 1C00002
if [ $? -ne 0 ]; then
    echo "TPM_writeekcert failed"
    ret=99
    break
fi

cat $EKECCCERT_FILE | \
env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_writeekcert 1C0000A
if [ $? -ne 0 ]; then
    echo "TPM_writeekcert failed"
    ret=99
fi

env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_transientempty
if [ $? -ne 0 ]; then
    echo "TPM transient area not empty => skipping"
    ret=99
    break
fi

TPMSTATE_FILE1=${TEST_BIN}_state1
TPMSTATE_FILE2=${TEST_BIN}_state2

env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_dumpstate>$TPMSTATE_FILE1
if [ $? -ne 0 ]; then
    echo "Error during dumpstate"
    ret=99
    break
fi

echo "Execute the test script"
env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    INTERMEDCA=$INTERMEDCA_FILE \
    ROOTCA=$ROOTCA_FILE \
    G_MESSAGES_DEBUG=all $@
ret=$?
echo "Script returned $ret"

#We check the state before a reboot to see if transients and NV were chagned.
env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_dumpstate>$TPMSTATE_FILE2
if [ $? -ne 0 ]; then
    echo "Error during dumpstate"
    ret=99
    break
fi

if [ "$(cat $TPMSTATE_FILE1)" != "$(cat $TPMSTATE_FILE2)" ]; then
    echo "TPM changed state during test"
    echo "State before ($TPMSTATE_FILE1):"
    cat $TPMSTATE_FILE1
    echo "State after ($TPMSTATE_FILE2):"
    cat $TPMSTATE_FILE2
    ret=1
    break
fi

break

#TODO: Add a tpm-restart/reboot here

#We check the state again after a reboot to see if PCR allocations were chagned.
env TPM20TEST_TCTI_NAME="socket" \
    TPM20TEST_SOCKET_ADDRESS="127.0.0.1" \
    TPM20TEST_SOCKET_PORT="${SIM_PORT_DATA}" \
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}" \
    G_MESSAGES_DEBUG=all ./test/helper/tpm_dumpstate>$TPMSTATE_FILE2
if [ $? -ne 0 ]; then
    echo "Error during dumpstate"
    ret=99
    break
fi

if [ "$(cat $TPMSTATE_FILE1)" != "$(cat $TPMSTATE_FILE2)" ]; then
    echo "TPM changed state during test"
    echo "State before ($TPMSTATE_FILE1):"
    cat $TPMSTATE_FILE1
    echo "State after ($TPMSTATE_FILE2):"
    cat $TPMSTATE_FILE2
    ret=1
    break
fi

break
done

# This sleep is sadly necessary: If we kill the tabrmd w/o sleeping for a
# second after the test finishes the simulator will die too. Bug in the
# simulator?
sleep 1
# teardown
daemon_stop ${SIM_PID_FILE}
rm -rf ${SIM_TMP_DIR} ${SIM_PID_FILE}

exit $ret
