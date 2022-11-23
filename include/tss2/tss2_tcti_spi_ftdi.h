/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */
#ifndef TSS2_TCTI_SPI_FTDI_H
#define TSS2_TCTI_SPI_FTDI_H

#include <stdbool.h>
#include "tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_Tcti_Spi_Ftdi_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *config);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_SPI_FTDI_H */
