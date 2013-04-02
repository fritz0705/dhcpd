#pragma once

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef DHCPD_DB_H_
#define DHCPD_DB_H_

static const char DB_SCHEMA[] =
"CREATE TABLE IF NOT EXISTS leases (\n"
"  'id' INTEGER PRIMARY KEY,\n"
"  'address' STRING NOT NULL UNIQUE,\n"
"  'prefixlen' INTEGER,\n"
"  'hwaddr' STRING NOT NULL UNIQUE COLLATE NOCASE,\n"
"  'routers' STRING,\n"
"  'nameservers' STRING,\n"
"  'leasetime' INTEGER,\n"
"  'allocated' BOOLEAN DEFAULT 0,\n"
"  'allocated_at' INTEGER\n"
");\n"
"CREATE INDEX IF NOT EXISTS leases_idx_address ON leases (\n"
"  'address'\n"
");\n"
"CREATE INDEX IF NOT EXISTS leases_idx_hwaddr ON leases (\n"
"  'hwaddr' COLLATE NOCASE\n"
");\n"
"CREATE INDEX IF NOT EXISTS leases_idx_allocated_at ON leases (\n"
"  'allocated_at' ASC\n"
");\n";

#define DB_LEASE_EMPTY {\
		.id = 0,\
		.address = NULL,\
		.prefixlen = 0,\
		.hwaddr = NULL,\
		.routers = NULL,\
		.nameservers = NULL,\
		.leasetime = 0,\
		.allocated = false,\
		.allocated_at = 0\
	}

struct db_lease
{
	unsigned int id;

	char *address;
	uint8_t prefixlen;
	char *hwaddr;

	char *routers;
	char *nameservers;

	uint8_t leasetime;
	bool allocated;
	time_t allocated_at;
};

static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

#endif

