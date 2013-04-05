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

static inline int db_lease_delete(sqlite3 *db, struct db_lease *lease)
{
	sqlite3_stmt *stmt;
	int sqlerr = sqlite3_prepare_v2(db,
		"DELETE FROM leases\n"
		"WHERE id = ?;\n", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
		return sqlite3_errcode(db);

	sqlite3_bind_int(stmt, 1, lease->id);

	sqlerr = sqlite3_step(stmt);
	if (stmt != SQLITE_OK)
	{
		sqlite3_finalize(stmt);
		return sqlerr;
	}

	sqlite3_finalize(stmt);
	return SQLITE_OK;
}

static inline void db_lease_from_lease(struct db_lease *dbl, struct dhcp_lease *l)
{
	size_t routers_len = INET_ADDRSTRLEN * l->routers_cnt + l->routers_cnt;
	size_t nameservers_len = INET_ADDRSTRLEN * l->nameservers_cnt + l->nameservers_cnt;

	*dbl = (struct db_lease){
		.id = 0,
		.address = malloc(INET_ADDRSTRLEN),
		.prefixlen = l->prefixlen,
		.hwaddr = NULL,
		.routers = malloc(routers_len),
		.nameservers = malloc(nameservers_len),
		.leasetime = l->leasetime,
		.allocated = false,
		.allocated_at = 0
	};

	dbl->routers[0] = 0;
	dbl->nameservers[0] = 0;

	iplist_dump(l->routers, l->routers_cnt, dbl->routers, routers_len-1);
	iplist_dump(l->nameservers, l->nameservers_cnt, dbl->nameservers,
		nameservers_len-1);
	inet_ntop(AF_INET, &l->address, dbl->address, INET_ADDRSTRLEN);
	printf("%s %s\n", dbl->routers, dbl->nameservers);
}

static inline void db_lease_from_stmt(sqlite3_stmt *stmt, struct db_lease *l)
{
	*l= (struct db_lease){
		.id = sqlite3_column_int(stmt, 0),
		.address = strdup((const char*)sqlite3_column_text(stmt, 1)),
		.prefixlen = sqlite3_column_int(stmt, 2),
		.hwaddr = strdup((const char*)sqlite3_column_text(stmt, 3)),
		.routers = strdup((const char*)sqlite3_column_text(stmt, 4)),
		.nameservers = strdup((const char*)sqlite3_column_text(stmt, 5)),
		.leasetime = sqlite3_column_int(stmt, 6),
		.allocated = sqlite3_column_int(stmt, 7),
		.allocated_at = sqlite3_column_int(stmt, 8),
	};
}

static inline int db_lease_by_hwaddr(sqlite3 *db,
	struct db_lease *lease, const char *hwaddr)
{
	sqlite3_stmt *stmt;
	int sqlerr = sqlite3_prepare_v2(db,
		"SELECT " DB_COLUMNS " FROM leases\n"
		"WHERE hwaddr = ?;\n", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
		return sqlite3_errcode(db);

	sqlite3_bind_text(stmt, 1, hwaddr, -1, NULL);

	sqlerr = sqlite3_step(stmt);
	if (sqlerr != SQLITE_DONE && sqlerr != SQLITE_ROW)
	{
		sqlite3_finalize(stmt);
		return sqlerr;
	}

	if (sqlerr != SQLITE_ROW)
	{
		lease->id = 0;
		sqlite3_finalize(stmt);
		return SQLITE_OK;
	}

	db_lease_from_stmt(stmt, lease);

	sqlite3_finalize(stmt);

	return SQLITE_OK;
}

static inline int db_lease_by_address(sqlite3 *db,
	struct db_lease *lease, const char *address)
{
	sqlite3_stmt *stmt;
	int sqlerr = sqlite3_prepare_v2(db,
		"SELECT " DB_COLUMNS " FROM leases\n"
		"WHERE address = ?;\n", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
		return sqlite3_errcode(db);

	sqlite3_bind_text(stmt, 1, address, -1, NULL);

	sqlerr = sqlite3_step(stmt);
	if (sqlerr != SQLITE_DONE && sqlerr != SQLITE_ROW)
	{
		sqlite3_finalize(stmt);
		return sqlerr;
	}

	if (sqlerr != SQLITE_ROW)
	{
		lease->id = 0;
		sqlite3_finalize(stmt);
		return SQLITE_OK;
	}

	db_lease_from_stmt(stmt, lease);

	sqlite3_finalize(stmt);

	return SQLITE_OK;
}

static inline int db_insert(sqlite3 *db, struct db_lease *lease)
{
	sqlite3_stmt *stmt;
	int sqlerr = sqlite3_prepare_v2(db,
		"INSERT INTO leases\n"
		"('address', 'prefixlen', 'hwaddr', 'routers', 'nameservers',\n"
		"'leasetime', 'allocated', 'allocated_at')\n"
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?);\n", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
		return sqlite3_errcode(db);

	sqlite3_bind_text(stmt, 1, lease->address, -1, NULL);
	sqlite3_bind_int(stmt, 2, lease->prefixlen);
	sqlite3_bind_text(stmt, 3, lease->hwaddr, -1, NULL);

	if (lease->routers)
		sqlite3_bind_text(stmt, 4, lease->routers, -1, NULL);
	if (lease->nameservers)
		sqlite3_bind_text(stmt, 5, lease->nameservers, -1, NULL);
	sqlite3_bind_int(stmt, 6, lease->leasetime);
	sqlite3_bind_int(stmt, 7, lease->allocated);
	sqlite3_bind_int(stmt, 8, lease->allocated_at);

	sqlerr = sqlite3_step(stmt);
	if (sqlerr != SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		return sqlerr;
	}

	lease->id = sqlite3_last_insert_rowid(db);
	sqlite3_finalize(stmt);

	return SQLITE_DONE;
}

static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

#endif

