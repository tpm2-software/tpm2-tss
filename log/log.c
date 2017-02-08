#include "log.h"

/*
 * This array of structures defines the mapping from the log_level
 * enumeration to their string representation.
 */
static const struct log_string {
    log_level   level;
    const char *string;
} log_strings [] = {
    {
        DEBUG,
        "DEBUG",
    },
    {
        INFO,
        "INFO",
    },
    {
        WARNING,
        "WARNING",
    },
    {
        ERROR,
        "ERROR",
    }
};
/*
 * This function converts a member of the log_level enumeration to its
 * string representation. It's a simple lookup in the log_strings array
 * defined above.
 */
const char*
level_to_str (log_level level)
{
    unsigned int i;
    for (i = 0; i < sizeof (log_strings) / sizeof (log_strings[0]); ++i) {
        if (level == log_strings[i].level) {
            return log_strings[i].string;
        }
    }
    return "unknown";
}
