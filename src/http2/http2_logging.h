#ifndef HTTP_LOGGING_H
#define HTTP_LOGGING_H

#include "stdio.h"

#define LOG_DEBUG_ENABLED

#define LOG_INFO(format, ...) printf("[HTTP2 INFO] " format "\n", ##__VA_ARGS__)

#ifdef LOG_DEBUG_ENABLED
#define LOG_DEBUG(format, ...) printf("[HTTP2 Debug] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) fprintf(stderr,"[HTTP2 Error] " format "\n", ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) fprintf(stderr,"[HTTP2 Error] " format "\n\t Reason: %s\n", strerror(errno), ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#define ERROR(format, ...)
#define SSL_ERORR(format, ...)
#endif

#endif
