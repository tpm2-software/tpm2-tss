/* SPDX-License-Identifier: BSD-2 */
#include <stdlib.h>

/*
 * esys_free is a helper function that is a wrapper around free().
 * This allows programs that are built using a different version
 * of the C runtime to free memory that has been allocated by the
 * esys library on Windows.
 */
void esys_free(void *__ptr) {
    if (__ptr != NULL) {
        free(__ptr);
    }
}