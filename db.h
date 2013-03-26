#pragma once

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

#include <sqlite3.h>

static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

