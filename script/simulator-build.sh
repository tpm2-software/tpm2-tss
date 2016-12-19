#!/bin/bash

# directories where we do stuff
SRCROOT_DIR=$(pwd)
TEST_DIR=${SRCROOT_DIR}/test
if [ -d "${TEST_DIR}" ]; then
    . $(dirname ${BASH_SOURCE[0]})/simulator.inc
else
    echo "Execute $0 from build root"; exit 1
fi

SIM_DIR=${TEST_DIR}/${SIM_NAME}
SIM_SRC_DIR=${SIM_DIR}/src

if [ ! -d ${SIM_DIR} ]; then
    mkdir ${SIM_DIR};
fi
cd "${SIM_DIR}"
if [ ! -f ${SIM_FILE} ]; then
    wget ${SIM_URL} || { echo "failed to wget ${SIM_URL}"; exit 1; }
fi

# ensure we got the simulator source we expect
sha256sum ${SIM_FILE} | grep "^${SIM_SHA}" || { echo "failed to validate simulator hash"; exit 1; }

# extract source and build it
tar -xf ${SIM_FILE} || { echo "failed to extract simulator source"; exit 1; }
cd "${SIM_SRC_DIR}" || { echo "failed to change dir to: ${SIM_SRC_DIR}"; exit 1; }
make -j$(nproc)     || { echo "failed to build simulator"; exit 1; }
