#ifndef LOG_H
#define LOG_H

#include <stdio.h>

#define print_log(fmt, ...) \
    do { \
        fprintf(stderr, \
                "%s:%d:%s(): " fmt "\n", \
                __FILE__, \
                __LINE__, \
                __func__, \
                ##__VA_ARGS__); \
    } while (0)
#define print_fail(fmt, ...) \
    do { \
        fprintf(stdout, \
                "%s:%d:%s(): " fmt "\n", \
                __FILE__, \
                __LINE__, \
                __func__, \
                ##__VA_ARGS__); \
         exit(1); \
    } while (0)

#endif
