-- Default database schema for dhcpd
-- sqlite3 eth0.db < schema.sql

CREATE TABLE IF NOT EXISTS leases (
	'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	'address' STRING NOT NULL,
	'hwaddr' STRING NOT NULL COLLATE NOCASE,
	'routers' STRING DEFAULT '',
	'nameservers' STRING DEFAULT '',
	'prefixlen' INTEGER DEFAULT 24,
	'leasetime' INTEGER DEFAULT 3600
);
CREATE UNIQUE INDEX IF NOT EXISTS leases__ix_hwaddr ON leases ('hwaddr' COLLATE NOCASE);

