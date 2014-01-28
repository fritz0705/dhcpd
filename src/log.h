#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>

#ifndef DHCPD_LOG_H_
#define DHCPD_LOG_H_

#define DHCPD_LOG_ERROR   (1 << 0)
#define DHCPD_LOG_WARNING (1 << 1)
#define DHCPD_LOG_NOTICE  (1 << 2)
#define DHCPD_LOG_DEBUG   (1 << 3)

#define dhcpd_log_DEBUG(...) dhcpd_log(DHCPD_LOG_DEBUG, __VA_ARGS__)
#define dhcpd_log_NOTICE(...) dhcpd_log(DHCPD_LOG_NOTICE, __VA_ARGS__)
#define dhcpd_log_WARNING(...) dhcpd_log(DHCPD_LOG_WARNING, __VA_ARGS__)
#define dhcpd_log_ERROR(...) dhcpd_log(DHCPD_LOG_ERROR, __VA_ARGS__)

unsigned dhcpd_log_mask;
FILE *dhcpd_log_stream;

bool dhcpd_logv(unsigned level, const char *fmt, va_list ap);
bool dhcpd_log(unsigned level, const char *fmt, ...);
unsigned dhcpd_log_mkmask(const char *str);
const char *dhcpd_log_str(unsigned m);

#endif
