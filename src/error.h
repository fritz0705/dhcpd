#pragma once

#include <stdlib.h>
#include <string.h>

#include "log.h"

#ifndef DHCPD_ERROR_H_
#define DHCPD_ERROR_H_

#define dhcpd_error(__exit, __errno, ...) do { \
		if (__errno) \
			dhcpd_log_ERROR(strerror(__errno)); \
		dhcpd_log_ERROR(__VA_ARGS__); \
		exit(__exit); \
	} while (0);

#define dhcpd_warn dhcpd_log_WARNING
#define dhcpd_notice dhcpd_log_NOTICE
#define dhcpd_debug dhcpd_log_DEBUG

#endif

