DHCP Daemon
===========

Simple, configurable, SQLite3-backed DHCP daemon. No enterprise grade features
like IPC to BIND (at the moment).

Usage
-----

```shell
make
sudo ./dhcpd -interface eth0 -allocate -new -iprange 192.168.0.2 192.168.0.254 \
             -router 192.168.0.1 -nameserver 192.168.0.1
```

