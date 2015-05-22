#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
//#define SUPPRESS_ALL_OUTPUT

#define F(level) \
    LOG_ ## level,

typedef enum log_level_t {
#include "logtypes.inc"
} log_level_t;
#undef F

int log_level(int level, FILE *stream, const char *fmt, ...);

#ifndef SUPPRESS_ALL_OUTPUT
#define LOG(LEVEL, s, ...) \
    log_level(LOG_ ## LEVEL, stdout, s, ##__VA_ARGS__)
#define SAFE_EPRINTF(v ...) do {                \
        char   buf[BUFSIZ];                     \
        size_t len = snprintf(buf, BUFSIZ, v);  \
        (void)write(STDERR_FILENO, buf, len); } while (0)
#else
#define LOG(LEVEL, s, ...) ((void)0)
#define SAFE_EPRINTF(v ...) ((void)0)
#endif

#define _SAFE_EPRINTF(v ...) do {                \
        char   buf[BUFSIZ];                     \
        size_t len = snprintf(buf, BUFSIZ, v);  \
        (void)write(STDERR_FILENO, buf, len); } while (0)
#endif
