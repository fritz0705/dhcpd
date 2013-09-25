#include "config.h"

bool config_fill(struct config *cfg, struct argv *argv)
{
	cfg->argv = argv;

	for (size_t i = 0; i < 2; ++i)
		if (argv->iprange[i])
			if (inet_pton(AF_INET, argv->iprange[i], &cfg->iprange[i]) != 1)
				goto invalid_iprange_address;

	if (argv->gc)
		cfg->gc = atoi(argv->gc);

	return true;

	switch (1)
	{
		default:
			break;

invalid_iprange_address:
			cfg->error = "Invalid IP range address";
			break;
	}

	config_free(cfg);
	return false;
}
