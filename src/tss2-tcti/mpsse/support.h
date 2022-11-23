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
/*
 * This file was copied from https://github.com/devttys0/libmpsse.git (sha1: a2eafa2)
 * and modified accordingly.
 *
 * Copyright (c) 2015, Craig Heffner
 * All rights reserved.
 * SPDX short identifier: BSD-2-Clause
 */
#ifndef _SUPPORT_H_
#define _SUPPORT_H_

#include "mpsse.h"

int raw_write (struct mpsse_context *mpsse, unsigned char *buf, int size);
int raw_read (struct mpsse_context *mpsse, unsigned char *buf, int size);
void set_timeouts (struct mpsse_context *mpsse, int timeout);
uint16_t freq2div (uint32_t system_clock, uint32_t freq);
uint32_t div2freq (uint32_t system_clock, uint16_t div);
unsigned char *build_block_buffer (struct mpsse_context *mpsse, uint8_t cmd, unsigned char *data, int size, int *buf_size);
int set_bits_high (struct mpsse_context *mpsse, int port);
int set_bits_low (struct mpsse_context *mpsse, int port);
int gpio_write (struct mpsse_context *mpsse, int pin, int direction);
int is_valid_context (struct mpsse_context *mpsse);

#endif
