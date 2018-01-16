#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stddef.h>

#ifndef LOGMODULE
#error "LOGMODULE must be set before including log/log.h"
#endif

#ifndef LOGDEFAULT
#define LOGDEFAULT LOGLEVEL_WARNING
#endif

#if defined (__GNUC__)
#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#else
#define COMPILER_ATTR(...)
#endif

typedef enum {
    LOGLEVEL_NONE     = 0,
    LOGLEVEL_ERROR    = 1,
    LOGLEVEL_WARNING  = 2,
    LOGLEVEL_INFO     = 3,
    LOGLEVEL_DEBUG    = 4,
    LOGLEVEL_TRACE    = 5,
    LOGLEVEL_UNDEFINED    = 0xff
} log_level;

static const char *log_strings[] COMPILER_ATTR(unused) = {
    "none",
    "ERROR",
    "WARNING",
    "info",
    "debug",
    "trace"
};

#define xstr(s) str(s)
#define str(s) #s

static log_level LOGMODULE_status COMPILER_ATTR(unused) = LOGLEVEL_UNDEFINED;

#if LOGLEVEL == LOGLEVEL_ERROR || \
    LOGLEVEL == LOGLEVEL_WARNING || \
    LOGLEVEL == LOGLEVEL_INFO || \
    LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
#define LOG_ERROR(FORMAT, ...) doLog(LOGLEVEL_ERROR, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     FORMAT, ## __VA_ARGS__)
#define LOGBLOB_ERROR(BUFFER, SIZE, FORMAT, ...) doLogBlob(LOGLEVEL_ERROR, \
                                             xstr(LOGMODULE), LOGDEFAULT, \
                                             &LOGMODULE_status, \
                                             __FILE__, __func__, __LINE__, \
                                             BUFFER, SIZE, \
                                             FORMAT, ## __VA_ARGS__)
#else /* LOGLEVEL >= LOGLEVEL_ERROR */
#define LOG_ERROR(FORMAT, ...) {}
#define LOGBLOB_ERROR(FORMAT, ...) {}
#endif /* LOGLEVEL >= LOGLEVEL_ERROR */

#if LOGLEVEL == LOGLEVEL_WARNING || \
    LOGLEVEL == LOGLEVEL_INFO || \
    LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
#define LOG_WARNING(FORMAT, ...) doLog(LOGLEVEL_WARNING, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     FORMAT, ## __VA_ARGS__)
#define LOGBLOB_WARNING(BUFFER, SIZE, FORMAT, ...) doLogBlob(LOGLEVEL_WARNING, \
                                                 xstr(LOGMODULE), LOGDEFAULT, \
                                                 &LOGMODULE_status, \
                                                 __FILE__, __func__, __LINE__, \
                                                 BUFFER, SIZE, \
                                                 FORMAT, ## __VA_ARGS__)
#else /* LOGLEVEL >= LOGLEVEL_WARNING */
#define LOG_WARNING(FORMAT, ...) {}
#define LOGBLOB_WARNING(FORMAT, ...) {}
#endif /* LOGLEVEL >= LOGLEVEL_WARNING */

#if LOGLEVEL == LOGLEVEL_INFO || \
    LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
#define LOG_INFO(FORMAT, ...) doLog(LOGLEVEL_INFO, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     FORMAT, ## __VA_ARGS__)
#define LOGBLOB_INFO(BUFFER, SIZE, FORMAT, ...) doLogBlob(LOGLEVEL_INFO, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     BUFFER, SIZE, \
                                     FORMAT, ## __VA_ARGS__)
#else /* LOGLEVEL >= LOGLEVEL_INFO */
#define LOG_INFO(FORMAT, ...) {}
#define LOGBLOB_INFO(FORMAT, ...) {}
#endif /* LOGLEVEL >= LOGLEVEL_INFO */

#if LOGLEVEL == LOGLEVEL_DEBUG || \
    LOGLEVEL == LOGLEVEL_TRACE
#define LOG_DEBUG(FORMAT, ...) doLog(LOGLEVEL_DEBUG, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     FORMAT, ## __VA_ARGS__)
#define LOGBLOB_DEBUG(BUFFER, SIZE, FORMAT, ...) doLogBlob(LOGLEVEL_DEBUG, \
                                             xstr(LOGMODULE), LOGDEFAULT, \
                                             &LOGMODULE_status, \
                                             __FILE__, __func__, __LINE__, \
                                             BUFFER, SIZE, \
                                             FORMAT, ## __VA_ARGS__)
#else /* LOGLEVEL >= LOGLEVEL_DEBUG */
#define LOG_DEBUG(FORMAT, ...) {}
#define LOGBLOB_DEBUG(FORMAT, ...) {}
#endif /* LOGLEVEL >= LOGLEVEL_DEBUG */

#if LOGLEVEL == LOGLEVEL_TRACE
#define LOG_TRACE(FORMAT, ...) doLog(LOGLEVEL_TRACE, \
                                     xstr(LOGMODULE), LOGDEFAULT, \
                                     &LOGMODULE_status, \
                                     __FILE__, __func__, __LINE__, \
                                     FORMAT, ## __VA_ARGS__)
#define LOGBLOB_TRACE(BUFFER, SIZE, FORMAT, ...) doLogBlob(LOGLEVEL_TRACE, \
                                             xstr(LOGMODULE), LOGDEFAULT, \
                                             &LOGMODULE_status, \
                                             __FILE__, __func__, __LINE__, \
                                             BUFFER, SIZE, \
                                             FORMAT, ## __VA_ARGS__)
#else /* LOGLEVEL >= LOGLEVEL_TRACE */
#define LOG_TRACE(FORMAT, ...) {}
#define LOGBLOB_TRACE(FORMAT, ...) {}
#endif /* LOGLEVEL >= LOGLEVEL_TRACE */

void
doLog(log_level loglevel, const char *module, log_level logdefault,
       log_level *status,
       const char *file, const char *func, int line,
       const char *msg, ...)
    COMPILER_ATTR(unused, format (printf, 8, 9));

void
doLogBlob(log_level loglevel, const char *module, log_level logdefault,
          log_level *status,
          const char *file, const char *func, int line,
          const uint8_t *buffer, size_t size, const char *msg, ...)
    COMPILER_ATTR(unused, format (printf, 10, 11));

#if defined(_MSC_VER)
inline char*
index (const char *s,
       int c)
{
    return strchr(s, c);
}

#define _CRT_DECLARE_NONSTDC_NAMES 1
#include <string.h>
inline int
strncasecmp (const char *s1,
             const char *s2,
             size_t len)
{
    return _strnicmp(s1, s2, len);
}
#endif /* _MSC_VER */
#endif /* LOG_H */
