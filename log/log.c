#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#define LOGMODULE log
#include "log/log.h"

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

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
        //log_strings[loglevel], module, file, func, line,
        vaargs);
    va_end(vaargs);
}

log_level
log_stringlevel(const char *n)
{
    for(log_level i = 0; i < sizeof(log_strings)/sizeof(log_strings[0]); i++) {
        if (strncasecmp(log_strings[i], n, strlen(log_strings[i])) == 0) {
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
    while ((i = index(i, '+')) != NULL) {
        if ((envlevel <= i - strlen("all") && strncasecmp(i - 3, "all", 3) == 0) ||
            (envlevel <= i - strlen(module) &&
             strncasecmp(i - strlen(module), module, strlen(module)) == 0)) {
            log_level tmp = log_stringlevel(i+1);
            if (tmp != LOGLEVEL_UNDEFINED)
                loglevel = tmp;
        }
        i = i + 1;
    }
    return loglevel;
}

