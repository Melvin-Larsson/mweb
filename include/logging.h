#ifndef LOGGING_H
#define LOGGING_H

#include "log_levels.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "errno.h"

#ifndef LOG_CONTEXT
#define LOG_CONTEXT __FILE__
#endif

#define CONSOLE

#ifdef CONSOLE
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define BLUE "\x1B[34m"
#define WHITE "\x1B[37m"
#define RESET "\x1B[0m"
#else
#define RED ""
#define GREEN ""
#define YELLOW ""
#define BLUE ""
#define WHITE ""
#define RESET ""
#endif

static const char *colors[] = {
    [LOG_LEVEL_TRACE] = WHITE,
    [LOG_LEVEL_DEBUG] = BLUE,
    [LOG_LEVEL_INFO] = GREEN,
    [LOG_LEVEL_WARNING] = YELLOW,
    [LOG_LEVEL_ERROR] = RED,
};

static const char *level_strings[] = {
    [LOG_LEVEL_TRACE] = "Trace",
    [LOG_LEVEL_DEBUG] = "Debug",
    [LOG_LEVEL_INFO] = "Info",
    [LOG_LEVEL_WARNING] = "Warning",
    [LOG_LEVEL_ERROR] = "Error",
};

static void log_message(FILE *file, int level, const char *format, va_list args) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm *t = localtime(&tv.tv_sec);

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
    fprintf(file, "%s", colors[level]);
    fprintf(file, "[%s.%03ld %s %s] ", timebuf, tv.tv_usec / 1000, LOG_CONTEXT, level_strings[level]);
    fprintf(file, RESET);

    vfprintf(file, format, args);
    fprintf(file, "\n");
}

static void log_printf(FILE *file, int level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(file, level, format, args);
    va_end(args);
}

#if LOG_LEVEL <= LOG_LEVEL_TRACE
#define LOG_TRACE(format, ...) log_printf(stdout, LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#else
#define LOG_TRACE(format, ...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_DEBUG
#define LOG_DEBUG(format, ...) log_printf(stdout, LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_INFO
#define LOG_INFO(format, ...) log_printf(stdout, LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#else
#define LOG_INFO(format, ...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_WARNING
#define LOG_WARNING(format, ...) log_printf(stdout, LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#else
#define LOG_WARNING(format, ...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_ERROR
#define ERROR(format, ...) log_printf(stderr, LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) log_printf(stderr, LOG_LEVEL_ERROR, format "\n\t Reason %s\n", ##__VA_ARGS__, strerror(errno))
#else
#define ERROR(format, ...)
#define ERRNO_ERROR(format, ...)
#endif


#endif
