#pragma once

#include <sqlite3.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include "iplist.h"
#include "dhcp.h"

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

#define DB_COLUMNS "id, address, prefixlen, hwaddr, routers, nameservers,\n"\
	"leasetime, allocated, allocated_at"

struct db_lease
{
	unsigned int id;

	char *address;
	uint8_t prefixlen;
	char *hwaddr;

	char *routers;
	char *nameservers;

	uint32_t leasetime;
	bool allocated;
	time_t allocated_at;
};

/**
 * Free any with a db_lease struct related memory areas
 *
 * @param[in] lease Struct which memory shall be freed
 */
static inline void db_lease_free(struct db_lease *lease)
{
	if (lease->routers)
		free(lease->routers);
	if (lease->nameservers)
		free(lease->nameservers);
	if (lease->hwaddr)
		free(lease->hwaddr);
	if (lease->address)
		free(lease->address);
}

/**
 * Delete record defined by a specified lease from database
 *
 * @param[in] db Database descriptor
 * @param[in] lease Struct which defines the lease which shall be deleted
 */
extern int db_lease_delete(sqlite3 *db, struct db_lease *lease);

/**
 * Fetch record by a specified hwaddr from database
 *
 * @param[in] db Database descriptor
 * @param[out] lease Struct which shall hold the database record
 * @param[in] hwaddr Textual representation of hwaddr
 */
extern int db_lease_by_hwaddr(sqlite3 *db, struct db_lease *lease,
	const char *hwaddr);

/**
 * Fetch record by a specified address from database
 *
 * @param[in] db Database descriptor
 * @param[out] lease Struct which shall hold the database record
 * @param[in] address Textual representation of address
 */
extern int db_lease_by_address(sqlite3 *db, struct db_lease *lease,
	const char *address);

/**
 * Insert lease record into database
 *
 * @param[in] db Database descriptor
 * @param[out] lease Struct which holds the record
 */
extern int db_insert(sqlite3 *db, struct db_lease *lease);

/**
 * Convert binary representation struct dhcp_lease to text representation
 * struct db_lease
 *
 * @param[out] dbl Struct which shall hold the text representation
 * @param[in] l Struct which holds the binary representation
 */
extern void db_lease_from_lease(struct db_lease *dbl, struct dhcp_lease *l);

/**
 * Put fetched row into struct db_lease from executed SQL statement
 *
 * @param[in] stmt Statement which was executed
 * @param[out] l Strutc which shall hold the row information
 */
extern void db_lease_from_stmt(sqlite3_stmt *stmt, struct db_lease *l);

/**
 * Initialize database with schema
 *
 * @param[in] db Database descriptor
 */
static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

#endif

