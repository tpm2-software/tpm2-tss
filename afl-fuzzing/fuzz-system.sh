#!/bin/bash
# SPDX-FileCopyrightText: 2022 - 2023 Juergen Repp
# SPDX-License-Identifier: BSD-2-Clause
#set -x
export srcdir=$(pwd)

trap killall afl-fuzz

test_endian=$(echo -n I | od -to2 | awk 'FNR==1{ print substr($2,6,1)}')
if [ $test_endian == 0 ]; then
    echo "Little endian test files can't be used on big endian architecture"
    exit 1
fi

mkdir -p afl-fuzzing/system-events
for x in binary_measurements_nuc.b64  binary_measurements_pc_client.b64
do
    base64 -d test/data/fapi/eventlog/$x > afl-fuzzing/system-events/${x%.b64}.bin
done

afl-clang-fast -flto -o fapi-system-fuzzing \
               test/unit/fapi-system-fuzzing.c \
               src/tss2-fapi/ifapi_json_eventlog_serialize.c \
               src/tss2-fapi/ifapi_ima_eventlog.c \
               src/tss2-fapi/ifapi_eventlog_system.c \
               src/tss2-fapi/ifapi_json_deserialize.c \
               src/tss2-fapi/ifapi_json_serialize.c \
               src/tss2-fapi/ifapi_policy_json_deserialize.c \
               src/tss2-fapi/ifapi_policy_json_serialize.c \
               src/tss2-fapi/tpm_json_deserialize.c \
               src/tss2-fapi/tpm_json_serialize.c \
               src/tss2-fapi/fapi_crypto.c \
               src/tss2-fapi/ifapi_eventlog.c \
               src/tss2-fapi/ifapi_helpers.c\
               src/tss2-fapi/ifapi_keystore.c  \
               src/tss2-fapi/ifapi_io.c \
               src/util/log.c \
               -DHAVE_CONFIG_H -I${srcdir} -I${srcdir}/include \
               -I${srcdir}/src -I${srcdir}/include \
               -I${srcdir}/include/tss2   -I${srcdir}/src/util -I${srcdir}/src/tss2-mu \
               -I${srcdir}/src/tss2-sys -I${srcdir}/src/tss2-esys -I${srcdir}/src/tss2-fapi \
               -I${srcdir}/test/data -Wno-unused-parameter -Wno-missing-field-initializers \
               -ljson-c -lcrypto -luuid

rm -r -f findings-system
AFL_SKIP_CPUFREQ=1 afl-fuzz -M fuzz0 -iafl-fuzzing/system-events/ -ofindings-system ./fapi-system-fuzzing @@ &

if [ ! -z "$1" ]; then
    for i in $(seq $1)
    do
        AFL_SKIP_CPUFREQ=1 afl-fuzz -S fuzz${i} -iafl-fuzzing/system-events -ofindings-system ./fapi-system-fuzzing @@ > /dev/null &
    done
fi
wait
cat findings-system/fuzz*/fuzzer_stats | grep uniq
