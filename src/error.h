#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DHCPD_ERROR_H_
#define DHCPD_ERROR_H_

static inline void dhcpd_error(int exit_, int errno_, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (errno_ != 0)
		fprintf(stderr, "%s: ", strerror(errno_));

	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);

	if (exit_ > 0)
		exit(exit_);
}

#endif

