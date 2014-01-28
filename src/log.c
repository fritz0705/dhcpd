#include "log.h"
#include "array.h"

static const char *dhcpd_log_strs[] = {
#define __LOGSTR(x) [DHCPD_LOG_##x] = #x
	__LOGSTR(ERROR),
	__LOGSTR(WARNING),
	__LOGSTR(NOTICE),
	__LOGSTR(DEBUG)
#undef __LOGSTR
};

unsigned dhcpd_log_mask = DHCPD_LOG_ERROR | DHCPD_LOG_WARNING;
FILE *dhcpd_log_stream = NULL;

bool dhcpd_logv(unsigned level, const char *fmt, va_list ap)
{
	if (!dhcpd_log_stream)
		dhcpd_log_stream = stderr;

	if (!fmt)
		return true;

	if (!(dhcpd_log_mask & level))
		return true;

	fprintf(dhcpd_log_stream, "%s: ", dhcpd_log_strs[level]);

	if (vfprintf(dhcpd_log_stream, fmt, ap) < 0)
		return false;

	fputc('\n', dhcpd_log_stream);

	return true;
}

bool dhcpd_log(unsigned level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	return dhcpd_logv(level, fmt, ap);
}

unsigned dhcpd_log_mkmask(const char *str)
{
	bool negate = false;
	unsigned mask = 0;
	while (*str)
	{
		switch (*str)
		{
			case '-':
				negate = true;
				goto next;
				
			case 'e':
			case 'E':
				if (negate)
					mask &= ~DHCPD_LOG_ERROR;
				else
					mask |= DHCPD_LOG_ERROR;
				break;

			case 'w':
			case 'W':
				if (negate)
					mask &= ~DHCPD_LOG_WARNING;
				else
					mask |= DHCPD_LOG_WARNING;
				break;

			case 'n':
			case 'N':
				if (negate)
					mask &= ~DHCPD_LOG_NOTICE;
				else
					mask |= DHCPD_LOG_NOTICE;
				break;

			case 'd':
			case 'D':
				if (negate)
					mask &= ~DHCPD_LOG_DEBUG;
				else
					mask |= DHCPD_LOG_DEBUG;
				break;
		}
		negate = false;
next:;
		 ++str;
	}
	return mask;
}

const char *dhcpd_log_str(unsigned m)
{
	if (m > ARRAY_LEN(dhcpd_log_strs))
		return NULL;
	return dhcpd_log_strs[m];
}
