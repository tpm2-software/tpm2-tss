#ifndef LOG_H
#define LOG_H

typedef enum {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    OFF
} log_level;

const char* level_to_str (log_level level);

#endif /* LOG_H */
