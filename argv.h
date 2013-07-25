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

	/* -user UID */
	char *user;
	/* -group GID */
	char *group;

	/* -iprange IP IP */
	char *iprange[2];

	/* -router IP */
	size_t routers_cnt;
	char **routers;

	/* -nameserver IP */
	size_t nameservers_cnt;
	char **nameservers;

	/* -prefixlen INT */
	char *prefixlen;

	/* -leasetime INT */
	char *leasetime;

	/* -help */
	bool help;
	/* -version */
	bool version;
	/* -debug */
	bool debug;
};

#define ARGV_EMPTY {\
		.argv = NULL,\
		.argc = 0,\
		.arg0 = NULL,\
		.interface = NULL,\
		.user = NULL,\
		.group = NULL,\
		.iprange = { NULL, NULL },\
		.routers = NULL,\
		.routers_cnt = 0,\
		.nameservers = NULL,\
		.nameservers_cnt = 0,\
		.help = false,\
		.version = false,\
		.debug = false,\
	}

/**
 * realloc callback for any allocation done by argv functions
 */
extern void *(* const argv_realloc)(void*, size_t);

/**
 * Parse argument list into struct argv and set special argv parameters
 *
 * @param[in] argc Count of arguments
 * @param[in] argv Argument list
 * @param[out] out Destination struct to write information
 */
extern bool argv_parse(int argc, char **argv, struct argv *out);

/**
 * Free any with a struct argv related memory
 *
 * @param[in] out Struct which related memory shall be freed
 */
static inline void argv_free(struct argv *out)
{
	if (out->routers)
		out->routers = argv_realloc(out->routers, out->routers_cnt = 0);
	if (out->nameservers)
		out->nameservers = argv_realloc(out->nameservers, out->nameservers_cnt = 0);
}
