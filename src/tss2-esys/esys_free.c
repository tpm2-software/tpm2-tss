/* SPDX-FileCopyrightText: 2018, David J. Maria @ fb.com */
/* SPDX-FileCopyrightText: 2018, Intel */
/* SPDX-FileCopyrightText: 2019, Infineon Technologies AG */
/* SPDX-FileCopyrightText: 2019, Alon Bar-Lev */
/* SPDX-FileCopyrightText: 2019, Fraunhofer SIT sponsored by Infineon */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>

/*
 * Esys_Free is a helper function that is a wrapper around free().
 * This allows programs that are built using a different version
 * of the C runtime to free memory that has been allocated by the
 * esys library on Windows.
 */
void Esys_Free(void *ptr) {
    free(ptr);
}
