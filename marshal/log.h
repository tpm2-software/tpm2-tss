#ifndef TSS2T_LOG_H

#define LOGMODULE marshal
#include "log/log.h"

#include <stdio.h>

#ifndef MARSHAL_LOG_LEVEL
#define MARSHAL_LOG_LEVEL WARNING
#endif

/*
 * This is a logging macro specific to the marshal module. The only thing
 * that makes it unique to this module though is the 'marshal' prefix. The
 * format for these messages is:
 * module:level:file:line:message
 * where:
 * - module : the name of the code module where the message originates
 * - level  : a string name for the logging level, see log.c
 * - file   : the name of the file where the message comes from
 * - line   : the line number where the LOG macro is invoked
 * - message: a textual message describing the event being logged
 * NOTE: this macro appends a newline to the message
 */
#define LOG(level, fmt, ...) \
    if (level >= MARSHAL_LOG_LEVEL) do { \
        fprintf (stderr, \
                 "%s:marshal:%s:%d " fmt "\n", \
                 log_strings[level], \
                 __FILE__, \
                 __LINE__, \
                 ##__VA_ARGS__); \
    } while (0)

#endif /* TSS2T_LOG_H */
