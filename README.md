DHCP Daemon
===========

Simple, configurable, SQLite3-backed DHCP daemon. No enterprise grade features
like IPC to BIND (at the moment).

Usage
-----

```
dhcpd [-h[elp]] [-v[ersion]] [-d[ebug]] [-user UID] [-group GID]
      [-interface IF] [-db FILE]
      [-new] [-allocate] [-iprange IP IP] [-router IP]... [-nameserver IP]...
```

<dl>
	<dt>-help</dt>
	<dd>Print help message and exit</dd>

	<dt>-version</dt>
	<dd>Print version information</dd>

	<dt>-debug</dt>
	<dd>Print information about incoming and outgoing messages</dd>

	<dt>-user UID</dt>
	<dd>Run as specified user, where UID is an integer or an username</dd>

	<dt>-group GID</dt>
	<dd>If -user is supplied, then the group will the specified group instead of
	    the primary group of user, where GID is an integer or a groupname</dd>
	
	<dt>-interface IF</dt>
	<dd>Run on interface IF</dd>

	<dt>-db FILE</dt>
	<dd>Use FILE as database</dd>

	<dt>-new</dt>
	<dd>Create database schema in specified database, useful if you're using
	    ':memory:' as database</dd>

	<dt>-allocate</dt>
	<dd>Allocate IP addresses from specified IP range</dd>

	<dt>-iprange IP IP</dt>
	<dd>Range of IP addresses, from which the daemon can allocate</dd>

	<dt>-router IP</dt>
	<dd>IP addresses of routers</dd>
	
	<dt>-nameserver IP</dt>
	<dd>IP addresses of nameservers</dd>
</dl>

