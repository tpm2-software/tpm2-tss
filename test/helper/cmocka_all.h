/* SPDX-FileCopyrightText: 2024, Infineon Technologies AG */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef CMOCKA_ALL_H
#define CMOCKA_ALL_H

/* CMocka is very strict about having a certain number of headers
 * being included before the cmocka.h include itself.
 * The purpose of this header is to enable exactly this in one
 * overall place.
 * Note: This header needs to be included at the top of the include section.
 */

// clang-format off
// IWYU pragma: begin_keep
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
// IWYU pragma: end_keep
#include <cmocka.h> // IWYU: export
// clang-format on

#endif // CMOCKA_ALL_H