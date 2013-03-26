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
	uint_least8_t routers_cnt;

	/* -nameserver IP */
	char **nameservers;
	uint_least8_t nameservers_cnt;

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

extern void *(*argv_realloc)(void*, size_t);

extern void argv_defaults(struct argv *opt);
extern bool argv_parse(int argc, char **argv, struct argv *out);

/* Free any dynamic allocated memory in the supplied struct */
static inline void argv_free(struct argv *out)
{
	if (out->routers)
		out->routers = argv_realloc(out->routers, out->routers_cnt = 0);
	if (out->nameservers)
		out->nameservers = argv_realloc(out->nameservers, out->nameservers_cnt = 0);
}

