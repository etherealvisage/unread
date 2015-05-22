#include "logger.h"

#include <stdarg.h>
#include <stdlib.h>

#define F(level) \
    "[" #level "]",
const char *level_names[] = {
#include "logtypes.inc"
};
#undef F

int log_level(int level, FILE *stream, const char *fmt, ...) {
    va_list ap;

    char buffer[4096];
    snprintf(buffer, sizeof buffer, "%-8s %s\n", level_names[level], fmt);

    va_start(ap, fmt);
    int ret = vfprintf(stream, buffer, ap);
    va_end(ap);

    if (level == LOG_FATAL) {
       abort();
    }
    return ret;
}
