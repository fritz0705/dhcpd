#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "argv.h"

struct config
{
	struct argv *argv;
	const char *error;

	struct in_addr *routers;
	size_t routers_cnt;

	struct in_addr *nameservers;
	size_t nameservers_cnt;

	struct in_addr iprange[2];
};

#define CONFIG_EMPTY {\
		.argv = NULL,\
		.routers = NULL,\
		.routers_cnt = 0,\
		.nameservers = NULL,\
		.nameservers_cnt = 0,\
		.iprange = {{0}, {0}}\
	}

extern bool config_fill(struct config *cfg, struct argv *argv);

static inline void config_free(struct config *cfg)
{
	if (cfg->routers)
		cfg->routers = realloc(cfg->routers, cfg->routers_cnt = 0);
	if (cfg->nameservers)
		cfg->nameservers = realloc(cfg->nameservers, cfg->nameservers_cnt = 0);
}

