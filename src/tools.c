#include <stdio.h>

#include "tools.h"

int mac_ntop(const char *addr, char *dst, size_t s)
{
	return snprintf(dst, s,
		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", 
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

