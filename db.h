#pragma once

static const char DB_SCHEMA[] =
"CREATE TABLE IF NOT EXISTS leases (\n"
"	'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
"	'address' STRING NOT NULL,\n"
"	'hwaddr' STRING NOT NULL COLLATE NOCASE,\n"
"	'routers' STRING DEFAULT '',\n"
"	'nameservers' STRING DEFAULT '',\n"
"	'prefixlen' INTEGER DEFAULT 24,\n"
"	'leasetime' INTEGER DEFAULT 3600\n"
");\n"
"CREATE UNIQUE INDEX IF NOT EXISTS leases__ix_hwaddr ON leases ('hwaddr' COLLATE NOCASE);\n";

#include <sqlite3.h>

static inline void db_init(sqlite3 *db)
{
	sqlite3_exec(db, DB_SCHEMA, NULL, NULL, NULL);
}

