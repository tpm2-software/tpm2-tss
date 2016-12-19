#!/bin/bash

SRCROOT_DIR=$(pwd)
TEST_DIR=${SRCROOT_DIR}/test

if [ -d ${TEST_DIR} ]; then
    . $(dirname ${BASH_SOURCE[0]})/simulator.inc
else
    echo "Execute $0 from build root"; exit 1
fi

SIM_DIR=${TEST_DIR}/${SIM_NAME}
SIM_SRC_DIR=${SIM_DIR}/src
PATH=${SIM_SRC_DIR}:${PATH}
DAEMON=$(which tpm_server)
PID_FILE=${TEST_DIR}/tpm_server.pid
START_MSG="Starting tpm_server daemon"
STOP_MSG="Stopping tpm_server daemon"

case $1 in
    start)
        echo -n "${START_MSG} ${DAEMON}: "
        nohup ${DAEMON} ${OPTIONS} > /dev/null 2>&1 &
        RET=$?
        PID=$!
        if [ ${RET} -eq 0 ]; then
            echo "success"
        else
            echo "failed"
            exit ${RET}
        fi
        echo ${PID} > ${PID_FILE}
        disown ${PID}
        ;;
    stop)
        echo -n "${STOP_MSG} ${DAEMON}: "
        if [ ! -f ${PID_FILE} ]; then
            echo "failed, no PID file"
            exit 1
        fi
        read PID < "${PID_FILE}"
        kill ${PID}
        RET=$?
        if [ ${RET} -ne 0 ]; then
            echo "failed to kill process with PID: ${PID}"
            exit ${RET}
        fi
        rm ${PID_FILE}
        echo "success"
        ;;
    status)
        echo -n "Status of ${DAEMON}: "
        if [ ! -f ${PID_FILE} ]; then
            echo "no PID file, stopped"
            exit 1
        fi
        read PID < "${PID_FILE}"
        if $(kill -0 "${PID}" 2> /dev/null); then
            echo "running"
        else
            echo "PID file, stopped"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
esac
