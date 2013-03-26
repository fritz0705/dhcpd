#include "argv.h"
#include <stdlib.h>

void *(*argv_realloc)(void*, size_t) = realloc;

#include <string.h>

enum argv_p_state
{
	_ARGV_S_ARGUMENT,

	/* Value for -interface */
	_ARGV_S_INTERFACE_VAL,
	/* Value for -db */
	_ARGV_S_DB_VAL,
	/* Value for -user */
	_ARGV_S_USER_VAL,
	/* Value for -group */
	_ARGV_S_GROUP_VAL,
	/* First value for -iprange */
	_ARGV_S_IPRANGE_VAL_1,
	/* Second value for -iprange */
	_ARGV_S_IPRANGE_VAL_2,
	/* Value for -router */
	_ARGV_S_ROUTERS_VAL,
	/* Value for -nameserver */
	_ARGV_S_NAMESERVERS_VAL,
	/* Value for -prefixlen */
	_ARGV_S_PREFIXLEN_VAL,
	/* Value for -leasetime */
	_ARGV_S_LEASETIME_VAL
};

bool argv_parse(int argc, char **argv, struct argv *out)
{
	enum argv_p_state state = _ARGV_S_ARGUMENT;

	out->argv = argv;
	out->argc = argc;
	out->arg0 = argv[0];

	for (int i = 1; i < argc; ++i)
	{
		char *arg = argv[i];
		switch (state)
		{
			case _ARGV_S_ARGUMENT:
				if (!strcmp(arg, "-interface"))
					state = _ARGV_S_INTERFACE_VAL;
				else if (!strcmp(arg, "-db"))
					state = _ARGV_S_DB_VAL;
				else if (!strcmp(arg, "-user"))
					state = _ARGV_S_USER_VAL;
				else if (!strcmp(arg, "-group"))
					state = _ARGV_S_GROUP_VAL;
				else if (!strcmp(arg, "-iprange"))
					state = _ARGV_S_IPRANGE_VAL_1;
				else if (!strcmp(arg, "-router"))
					state = _ARGV_S_ROUTERS_VAL;
				else if (!strcmp(arg, "-nameserver"))
					state = _ARGV_S_NAMESERVERS_VAL;
				else if (!strcmp(arg, "-allocate"))
					out->allocate = true;
				else if (!strcmp(arg, "-help"))
					out->help = true;
				else if (!strcmp(arg, "-version"))
					out->version = true;
				else if (!strcmp(arg, "-debug"))
					out->debug = true;
				else if (!strcmp(arg, "-new"))
					out->_new = true;
				else if (!strcmp(arg, "-prefixlen"))
					state = _ARGV_S_PREFIXLEN_VAL;
				else if (!strcmp(arg, "-leasetime"))
					state = _ARGV_S_LEASETIME_VAL;
				else
				{
					out->argerror = i;
					return false;
				}
				break;

			case _ARGV_S_INTERFACE_VAL:
				out->interface = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_DB_VAL:
				out->db = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_USER_VAL:
				out->user = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_GROUP_VAL:
				out->group = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_IPRANGE_VAL_1:
				out->iprange[0] = arg;
				state = _ARGV_S_IPRANGE_VAL_2;
				break;

			case _ARGV_S_IPRANGE_VAL_2:
				out->iprange[1] = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_ROUTERS_VAL:
				out->routers = realloc(out->routers, ++out->routers_cnt * sizeof(char*));
				out->routers[out->routers_cnt - 1] = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_NAMESERVERS_VAL:
				out->nameservers = realloc(out->nameservers, ++out->nameservers_cnt * sizeof(char*));
				out->nameservers[out->nameservers_cnt - 1] = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_LEASETIME_VAL:
				out->leasetime = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_PREFIXLEN_VAL:
				out->prefixlen = arg;
				state = _ARGV_S_ARGUMENT;
				break;
		}
	}

	if (state != _ARGV_S_ARGUMENT)
	{
		out->argerror = -1;
		return false;
	}

	return true;
}

