#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {

	echo "Download deps for $DOCKER_TAG"

	if [ "$DOCKER_TAG" = "fedora-30" ]; then
		yum -y install libgcrypt-devel
	elif [ "$DOCKER_TAG" = "opensuse-leap" ]; then
		zypper -n in libgcrypt-devel
	elif [ "$DOCKER_TAG" = "ubuntu-16.04" -o "$DOCKER_TAG" = "ubuntu-18.04" ]; then
		apt-get -y install libgcrypt20-dev
	fi
}
