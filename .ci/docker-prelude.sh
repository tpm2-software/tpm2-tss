#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2019 - 2021 Intel
# SPDX-FileCopyrightText: 2022 Fraunhofer SIT sponsored by Infineon
# SPDX-License-Identifier: BSD-3-Clause

# all command failures are fatal
set -e

WORKSPACE=`dirname $DOCKER_BUILD_DIR`

echo "Workspace: $WORKSPACE"

source $DOCKER_BUILD_DIR/.ci/download-deps.sh

get_deps "$WORKSPACE"

export LD_LIBRARY_PATH=/usr/local/lib/

# Change to the build dir
echo "echo changing to $DOCKER_BUILD_DIR"
cd $DOCKER_BUILD_DIR

# workaround to solve problem with unsafe directory with alpine
git config --global --add safe.directory /workspace/tpm2-tss
