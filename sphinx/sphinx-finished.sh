#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024, Juergen Repp
# SPDX-License-Identifier: BSD-2-Clause

#
# This script is configured to run as part of the sphinx build
# through API events registered in conf.py.
# This script runs on event build-finished.
#
# This would be better served by handling the events
# html-collect-page --> for add .nojekyll
# html-page-context --> for fixing the span's done with sed.
#
# For the case of time, we just left this script as is and run it as a
# post sphinx build command event :-p
#

set -eo pipefail

find "${SPHINX_OUTDIR}" -name \*.html -exec \
  sed -i 's/\&amp;\#/\&\#/g' {} \;
touch "${SPHINX_OUTDIR}"/.nojekyll

exit 0
