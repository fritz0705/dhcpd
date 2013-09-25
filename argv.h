#pragma once

#ifndef DHCPD_ARGV_H_
#define DHCPD_ARGV_H_

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

	/* -template KEY */
	char *tpl;

	/* -gc INT */
	char *gc;

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
		.allocate = false,\
		.help = false,\
		.version = false,\
		.debug = false,\
		.tpl = NULL,\
		._new = false\
	}

/**
 * realloc callback for any allocation done by argv functions
 */
extern void *(*argv_realloc)(void*, size_t);

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
	(void)out;
}

#endif

