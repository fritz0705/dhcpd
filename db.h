#pragma once

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef DHCPD_DB_H_
#define DHCPD_DB_H_

static const char DB_SCHEMA[] =
"CREATE TABLE IF NOT EXISTS leases (\n"
"	'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
"	'address' STRING NOT NULL UNIQUE,\n"
"	'hwaddr' STRING NOT NULL UNIQUE COLLATE NOCASE,\n"
"	'routers' STRING DEFAULT '',\n"
"	'nameservers' STRING DEFAULT '',\n"
"	'prefixlen' INTEGER DEFAULT 24,\n"
"	'leasetime' INTEGER DEFAULT 3600,\n"
"	'allocated' BOOLEAN DEFAULT 0\n"
");\n";

#define DB_LEASE_EMPTY {\
		.id = 0,\
		.address = NULL,\
		.hwaddr = NULL,\
		.routers = NULL,\
		.nameservers = NULL,\
		.prefixlen = 0,\
		.leasetime = 0,\
		.allocated = false\
	}

struct db_lease
{
	unsigned int id;
	char *address;
	char *hwaddr;
	char *routers;
	char *nameservers;
	uint8_t prefixlen;
	uint32_t leasetime;
	bool allocated;
};

static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

#endif

