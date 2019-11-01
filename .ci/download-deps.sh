#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {
    git clone https://github.com/microsoft/ms-tpm-20-ref.git
    cd ms-tpm-20-ref/TPMCmd
    ./bootstrap
    # Work around a bug in ms-tpm-20-ref until the fix in
    # https://github.com/microsoft/ms-tpm-20-ref/pull/39 is merged upstream
    ./configure CPPFLAGS='-DTABLE_DRIVEN_MARSHAL=NO'
    make
    make install
}
