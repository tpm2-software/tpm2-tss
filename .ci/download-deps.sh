#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2019 Intel
# SPDX-FileCopyrightText: 2019 Fraunhofer SIT sponsored by Infineon
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {

	# Alpine packages Mbed TLS 4.x, but the image doesn't include it
	if [ "$WITH_CRYPTO" == "mbed" ] && [ -f /etc/alpine-release ]; then
		apk add --no-cache mbedtls-dev
	else
		echo "no deps"
	fi
}
