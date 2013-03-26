#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* This is our command line parser, at the moment it lacks a lexer and
 * therefore it can only applied to tokenized input.
 */

struct argv
{
	char **argv;
	int argc;
	int argerror;

	char *arg0;

	/* -interface IF */
	char *interface;
	/* -db FILE */
	char *db;
	/* -user UID */
	char *user;
	/* -group GID */
	char *group;

	/* -iprange IP IP */
	char *iprange[2];

	/* -router IP */
	char **routers;
	size_t routers_cnt;

	/* -nameserver IP */
	char **nameservers;
	size_t nameservers_cnt;

	/* -prefixlen INT */
	char *prefixlen;

	/* -leasetime INT */
	char *leasetime;

	/* -allocate */
	bool allocate;
	/* -help */
	bool help;
	/* -version */
	bool version;
	/* -debug */
	bool debug;
	/* -new */
	bool _new;
};

#define ARGV_EMPTY {\
		.argv = NULL,\
		.argc = 0,\
		.arg0 = NULL,\
		.interface = NULL,\
		.db = NULL,\
		.user = NULL,\
		.group = NULL,\
		.iprange = { NULL, NULL },\
		.routers = NULL,\
		.routers_cnt = 0,\
		.nameservers = NULL,\
		.nameservers_cnt = 0,\
		.allocate = false,\
		.help = false,\
		.version = false,\
		.debug = false,\
		._new = false\
	}

extern void *(*argv_realloc)(void*, size_t);

extern bool argv_parse(int argc, char **argv, struct argv *out);

/* Free any dynamic allocated memory in the supplied struct */
static inline void argv_free(struct argv *out)
{
	if (out->routers)
		out->routers = argv_realloc(out->routers, out->routers_cnt = 0);
	if (out->nameservers)
		out->nameservers = argv_realloc(out->nameservers, out->nameservers_cnt = 0);
}

