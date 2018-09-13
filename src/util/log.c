#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#define LOGMODULE log
#include "log.h"

#if !defined(_MSC_VER) || defined(__INTEL_COMPILER)
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
/* Microsoft Visual Studio gives internal error C1001 with _builtin_expect */
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/**
 * Compares two strings byte by byte and ignores the
 * character's case. Stops at the n-th byte of both
 * strings.
 *
 * This is basically a replacement of the POSIX-function
 * _strncasecmp_. Since tpm2-tss is supposed to be compatible
 * with ISO C99 and not with POSIX, _strncasecmp_ had to be
 * replaced. This function creates lowercase representations
 * of the strings to compare and calls the function _strncmp_
 * on them.
 *
 * @param string1 The first of the two strings to compare
 * @param string2 The second of the two strings to compare
 * @param n The maximum number of bytes to compare
 * @return 0 if both strings are equal (case insensitive),
 *  an integer greater than zero if string1 is greater than
 *  string 2 and an integer smaller than zero if string1 is
 *  smaller than string2
 *
 */
static int
case_insensitive_strncmp(const char *string1,
        const char *string2,
        size_t n)
{
    if ((string1 == NULL) && (string2 == NULL)) {
        return 0;
    }
    if ((string1 == NULL) && (string2 != NULL)) {
        return -1;
    }
    if ((string1 != NULL) && (string2 == NULL)) {
        return 1;
    }

    size_t string1_size = strlen (string1);
    size_t string2_size = strlen (string2);
    unsigned char lower_string1 [string1_size];
    unsigned char lower_string2 [string2_size];

    for (size_t i = 0; i < string1_size; i++)
        lower_string1[i] = tolower(string1[i]);

    for (size_t i = 0; i < string2_size; i++)
        lower_string2[i] = tolower(string2[i]);

    return memcmp (lower_string1, lower_string2, n);
}

log_level
getLogLevel(const char *module, log_level logdefault);

void
doLogBlob(log_level loglevel, const char *module, log_level logdefault,
           log_level *status,
           const char *file, const char *func, int line,
           const uint8_t *blob, size_t size, const char *fmt, ...)
{
    if (unlikely(*status == LOGLEVEL_UNDEFINED))
        *status = getLogLevel(module, logdefault);

    if (loglevel > *status)
        return;

    size_t width = 8;
    size_t buffer_size = (size * 2) + (size / width) * 2 + 1;
    char buffer[buffer_size];
    buffer[0] = '\0';
    for (size_t i = 0, off = 0; i < size && off < buffer_size; i++, off+=2) {
        if (width < buffer_size && i % width == 0) {
            *(&buffer[0] + off) = '\n';
            off += 1;
            *(&buffer[0] + off) = '\t';
            off += 1;
        }
        sprintf(&buffer[0] + off, "%02x", blob[i]);
    }

    va_list vaargs;
    va_start(vaargs, fmt);
    /* TODO: Unfortunately, vsnprintf(NULL, 0, ...) do not behave the same as
       snprintf(NULL, 0, ...). Until there is an alternative, messages on
       logblob are restricted to 255 characters
    int msg_len = vsnprintf(NULL, 0, fmt, vaargs); */
    int msg_len = 255;
    char msg[msg_len+1];
    vsnprintf(msg, sizeof(msg), fmt, vaargs);
    va_end(vaargs);

    doLog(loglevel, module, logdefault, status, file, func, line,
          "%s (size=%zi): %s", msg, size, buffer);
}

void
doLog(log_level loglevel, const char *module, log_level logdefault,
           log_level *status,
           const char *file, const char *func, int line,
           const char *msg, ...)
{
    if (unlikely(*status == LOGLEVEL_UNDEFINED))
        *status = getLogLevel(module, logdefault);

    if (loglevel > *status)
        return;

    int size = snprintf(NULL, 0, "%s:%s:%s:%d:%s() %s \n",
                log_strings[loglevel], module, file, line, func, msg);
    char fmt[size+1];
    snprintf(fmt, sizeof(fmt), "%s:%s:%s:%d:%s() %s \n",
                log_strings[loglevel], module, file, line, func, msg);

    va_list vaargs;
    va_start(vaargs, msg);
    vfprintf (stderr, fmt,
        /* log_strings[loglevel], module, file, func, line, */
        vaargs);
    va_end(vaargs);
}

log_level
log_stringlevel(const char *n)
{
    for(log_level i = 0; i < sizeof(log_strings)/sizeof(log_strings[0]); i++) {
        if (case_insensitive_strncmp(log_strings[i], n, strlen(log_strings[i])) == 0) {
            return i;
        }
    }
    return LOGLEVEL_UNDEFINED;
}

log_level
getLogLevel(const char *module, log_level logdefault)
{
    log_level loglevel = logdefault;
    char *envlevel = getenv("TSS2_LOG");
    char *i = envlevel;
    if (envlevel == NULL)
        return loglevel;
    while ((i = strchr(i, '+')) != NULL) {
        if ((envlevel <= i - strlen("all") &&
	     case_insensitive_strncmp(i - 3, "all", 3) == 0) ||
            (envlevel <= i - strlen(module) &&
             case_insensitive_strncmp(i - strlen(module), module, strlen(module)) == 0)) {
            log_level tmp = log_stringlevel(i+1);
            if (tmp != LOGLEVEL_UNDEFINED)
                loglevel = tmp;
        }
        i = i + 1;
    }
    return loglevel;
}

