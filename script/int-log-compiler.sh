#!/usr/bin/env bash
#;**********************************************************************;
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017 - 2020, Intel Corporation
# Copyright (c) 2018 - 2020, Fraunhofer SIT sponsored by Infineon Technologies AG
#
# All rights reserved.
#;**********************************************************************;

# source the int-log-compiler-common sript
. ${srcdir}/script/int-log-compiler-common.sh

sanity_test

# start simulator if needed
if [[ ${INTEGRATION_TCTI} == *mssim* || ${INTEGRATION_TCTI} == *swtpm* ]]; then
    echo "Trying to start simulator ${INTEGRATION_TCTI}"
    try_simulator_start
fi

TPM20TEST_TCTI="${INTEGRATION_TCTI}"

# if $TPM20TEST_TCTI ends with mssim or swtpm (i.e. there is no config), add config:
TCTI_SIM_CONF="host=127.0.0.1,port=${SIM_PORT_DATA-}"
TPM20TEST_TCTI=${TPM20TEST_TCTI/%mssim/mssim:$TCTI_SIM_CONF}
TPM20TEST_TCTI=${TPM20TEST_TCTI/%swtpm/swtpm:$TCTI_SIM_CONF}

# Add pcap-tcti as wrapper
# TPM20TEST_TCTI="pcap:${TPM20TEST_TCTI}"
TCTI_PCAP_FILE="${@: -1}.pcap"
# rm -f "$TCTI_PCAP_FILE"


echo "TPM20TEST_TCTI=${TPM20TEST_TCTI}"

echo "Execute the test script"
env TPM20TEST_TCTI="${TPM20TEST_TCTI}" \
    TCTI_PCAP_FILE="${TCTI_PCAP_FILE}" \
    G_MESSAGES_DEBUG=all \
    ${@: -1}
ret=$?
echo "Script returned $ret"

if [[ ${TPM20TEST_TCTI} == *mssim* || ${TPM20TEST_TCTI} == *swtpm* ]]; then
    # This sleep is sadly necessary: If we kill the tabrmd w/o sleeping for a
    # second after the test finishes the simulator will die too. Bug in the
    # simulator?
    sleep 1
    # teardown
    daemon_stop ${SIM_PID_FILE}
    rm -rf ${SIM_TMP_DIR} ${SIM_PID_FILE}
fi

exit $ret
