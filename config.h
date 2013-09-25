#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "argv.h"

#ifndef DHCPD_CONFIG_H_
#define DHCPD_CONFIG_H_

struct config
{
	struct argv *argv;
	const char *error;

	struct in_addr iprange[2];

	uint32_t gc;
};

#define CONFIG_INIT {\
		.argv = NULL,\
		.iprange = {{0}, {0}},\
		.gc = 0\
	}

/**
 * Fill configuration struct from argv struct
 *
 * @param[out] cfg Destination struct config to write information
 * @param[in] argv Source argv struct
 */
extern bool config_fill(struct config *cfg, struct argv *argv);

/**
 * Free any with a configuration struct related memory areas
 */
static inline void config_free(struct config *cfg)
{
	(void)cfg;
}

#endif

