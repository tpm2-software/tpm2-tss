#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

# all command failures are fatal
set -e

WORKSPACE=`dirname $DOCKER_BUILD_DIR`

echo "Workspace: $WORKSPACE"

source $DOCKER_BUILD_DIR/.ci/download-deps.sh

get_deps "$WORKSPACE"

export LD_LIBRARY_PATH=/usr/local/lib/

echo "echo changing to $DOCKER_BUILD_DIR"
# Change to the the travis build dir
cd $DOCKER_BUILD_DIR
