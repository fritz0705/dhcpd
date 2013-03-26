DHCP Daemon
===========

Simple, configurable, SQLite3-backed DHCP daemon. No enterprise grade features
like IPC to BIND (at the moment).

Usage
-----

```shell
make
sqlite3 eth0.db < schema.sql
sudo ./dhcpd -interface eth0
```

