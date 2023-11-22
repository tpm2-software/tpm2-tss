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

# if $TPM20TEST_TCTI ends with libtpms (i.e. there is no config), add config:
# for FAPI, we need a state file which persists accross different processes
TCTI_LIBTPMS_CONF="${@: -1}.libtpms"
TPM20TEST_TCTI=${TPM20TEST_TCTI/%libtpms/libtpms:$TCTI_LIBTPMS_CONF}
rm -f "${TCTI_LIBTPMS_CONF}"

# Add pcap-tcti as wrapper
# TPM20TEST_TCTI="pcap:${TPM20TEST_TCTI}"
TCTI_PCAP_FILE="${@: -1}.pcap"
# rm -f "$TCTI_PCAP_FILE"


echo "TPM20TEST_TCTI=${TPM20TEST_TCTI}"

while true; do

INTERMEDCA_FILE=ca/intermed-ca/intermed-ca.cert
ROOTCA_FILE=ca/root-ca/root-ca.cert

echo "Execute the test script"
if [[ ${TPM20TEST_TCTI} == *device* ]]; then
    # No root certificate needed
    env TPM20TEST_TCTI="${TPM20TEST_TCTI}" \
        TCTI_PCAP_FILE="${TCTI_PCAP_FILE}" \
        G_MESSAGES_DEBUG=all ${@: -1}
else
    # Run test with generated certificate.

    EKECCCERT_PEM_FILE=${TEST_BIN}_ekecccert.pem
    export FAPI_TEST_CERTIFICATE_ECC="${EKECCCERT_PEM_FILE}"
    EKCERT_PEM_FILE=${TEST_BIN}_ekcert.pem
    export FAPI_TEST_CERTIFICATE="${EKCERT_PEM_FILE}"

    env TPM20TEST_TCTI="${TPM20TEST_TCTI}" \
        TCTI_PCAP_FILE="${TCTI_PCAP_FILE}" \
        FAPI_TEST_ROOT_CERT=${ROOTCA_FILE}.pem \
        FAPI_TEST_INT_CERT=${INTERMEDCA_FILE}.pem \
        G_MESSAGES_DEBUG=all ${@: -1}
fi
ret=$?
echo "Script returned $ret"

#TODO: Add a tpm-restart/reboot here

break
done

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
