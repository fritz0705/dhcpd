#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DHCPD_ERROR_H_
#define DHCPD_ERROR_H_

static inline void dhcpd_error(int _exit, int _errno, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (_errno != 0)
		fprintf(stderr, "%s: ", strerror(_errno));

	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);

	if (_exit > 0)
		exit(_exit);
}

#endif

