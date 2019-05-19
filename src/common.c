#include <stdarg.h>
#include <string.h>
#include "common.h"

extern char **environ;

uint64_t get_timenow(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
static uint16_t initialized = FALSE;
static log_level_t log_level;
char log_level_str[log_level_end][10] = {"error", "warn ", "debug", "info "};
void write_log(log_level_t level, const char *file, const char *func, const int line, const char *format, ...) {
    va_list ap;
    struct timeval tv;
    time_t now;
    struct tm *tm_now;
    if (level > log_level || level >= log_level_end)
        return;
    gettimeofday(&tv, NULL);
    now = (time_t)tv.tv_sec;
    tm_now = localtime(&now);
    va_start(ap, format);
    fprintf(stdout, "level:%s %d-%02d-%02d %02d:%02d:%02d.%06lu [%s:%s:%d]:", log_level_str[level],
            tm_now->tm_year + 1900, tm_now->tm_mon, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
            tv.tv_usec, func, file, line);
    vfprintf(stdout, format, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

void sys_init() {
    assert(!initialized);
    initialized = TRUE;
}

void set_log_level(log_level_t level) { log_level = level; }

void process_rename(char *new_name, char **argv) {
    int len, i;
    int offset;
    char *ptr;
    if (strlen(new_name) <= strlen(argv[0])) {
        memcpy(argv[0], new_name, strlen(new_name) + 1);
        return;
    }
    len = strlen(new_name) + 1;
    offset = strlen(new_name) - strlen(argv[0]);
    for (i = 1; argv[i]; i++) {
        len += strlen(argv[i]) + 1;
    }
    for (i = 0; environ[i]; i++) {
        len += strlen(environ[i]) + 1;
    }
    ptr = malloc(len);
    if (!ptr)
        return;
    memset(ptr, 0, len);
    if (argv[1])
        memmove(ptr + strlen(new_name) + 1, argv[1], len - strlen(new_name) - 1);
    else
        memmove(ptr + strlen(new_name) + 1, environ[0], len - strlen(new_name) - 1);

    for (i = 1; argv[i]; i++) {
        argv[i] = ptr + (argv[i] - argv[0] + offset);
    }
    for (i = 0; environ[i]; i++) {
        environ[i] = ptr + (environ[i] - argv[0] + offset);
    }
    offset = strlen(new_name) + 1;
    strncpy(argv[0], new_name, offset);
    for (i = 1; argv[i]; i++) {
        argv[0][offset - 1] = ' ';
        strncpy(argv[0] + offset, argv[i], strlen(argv[i]) + 1);
        offset += strlen(argv[i]) + 1;
    }
}