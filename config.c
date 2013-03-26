#include "config.h"

bool config_fill(struct config *cfg, struct argv *argv)
{
	cfg->argv = argv;

	for (size_t i = 0; i < argv->routers_cnt; ++i)
	{
		cfg->routers = realloc(cfg->routers, ++cfg->routers_cnt);
		if (inet_pton(AF_INET, argv->routers[i], &cfg->routers[cfg->routers_cnt-1]) != 1)
			goto invalid_router_address;
	}

	for (size_t i = 0; i < argv->nameservers_cnt; ++i)
	{
		cfg->nameservers = realloc(cfg->nameservers, ++cfg->nameservers_cnt);
		if (inet_pton(AF_INET, argv->nameservers[i], &cfg->nameservers[cfg->nameservers_cnt-1]) != 1)
			goto invalid_nameserver_address;
	}

	for (size_t i = 0; i < 2; ++i)
		if (argv->iprange[i])
			if (inet_pton(AF_INET, argv->iprange[i], &cfg->iprange[i]) != 1)
				goto invalid_iprange_address;

	return true;

	switch (1)
	{
		default:
			break;

invalid_nameserver_address:
			cfg->error = "Invalid nameserver address";
			break;

invalid_iprange_address:
			cfg->error = "Invalid IP range address";
			break;

invalid_router_address:
			cfg->error = "Invalid router address";
			break;
	}

	config_free(cfg);
	return false;
}
