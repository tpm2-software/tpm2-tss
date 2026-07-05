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

/*
 * Compatibility layer for typed cmocka macros.
 *
 * Newer cmocka versions deprecate the untyped mock helper macros such as
 * check_expected(), expect_value(), and will_return_always() in favor of
 * typed variants like check_expected_int(), expect_uint_value(), and
 * will_return_int_always().
 *
 * Older cmocka versions do not provide these typed variants yet. Define them
 * here as fallbacks to the older untyped macros so the unit tests can use the
 * modern API while still building with older cmocka releases.
 *
 * Pointer mock values are handled through mock_ptr_type() / will_return_ptr()
 * when available. For older cmocka versions, fall back to mock() /
 * will_return(), matching the historical behavior.
 */

#ifndef check_expected_int
#define check_expected_int(parameter) check_expected(parameter)
#endif

#ifndef check_expected_uint
#define check_expected_uint(parameter) check_expected(parameter)
#endif

#ifndef expect_int_value
#define expect_int_value(function, parameter, value) expect_value(function, parameter, value)
#endif

#ifndef expect_uint_value
#define expect_uint_value(function, parameter, value) expect_value(function, parameter, value)
#endif

#ifndef expect_int_value_count
#define expect_int_value_count(function, parameter, value, count)                                  \
    expect_value_count(function, parameter, value, count)
#endif

#ifndef expect_uint_value_count
#define expect_uint_value_count(function, parameter, value, count)                                 \
    expect_value_count(function, parameter, value, count)
#endif

#ifndef will_return_int
#define will_return_int(function, value) will_return(function, value)
#endif

#ifndef will_return_uint
#define will_return_uint(function, value) will_return(function, value)
#endif

#ifndef will_return_int_always
#define will_return_int_always(function, value) will_return_always(function, value)
#endif

#ifndef will_return_uint_always
#define will_return_uint_always(function, value) will_return_always(function, value)
#endif

#ifndef will_return_int_count
#define will_return_int_count(function, value, count) will_return_count(function, value, count)
#endif

#ifndef will_return_uint_count
#define will_return_uint_count(function, value, count) will_return_count(function, value, count)
#endif

#ifndef mock_ptr_type
#define mock_ptr_type(type) ((type)mock())
#endif

#ifndef will_return_ptr
#define will_return_ptr(function, value) will_return(function, value)
#endif

#endif // CMOCKA_ALL_H
