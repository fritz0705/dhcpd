/* (c) 2013 Fritz Conrad Grimpen */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/capability.h>
#include <sys/prctl.h>
#endif

#include <pwd.h>
#include <grp.h>

#include <ev.h>
#include <sqlite3.h>

#include "array.h"
#include "dhcp.h"
#include "argv.h"
#include "error.h"
#include "db.h"
#include "config.h"

#define RECV_BUF_LEN 4096
#define SEND_BUF_LEN 4096

sqlite3 *leasedb;

struct sockaddr_in server_id;
struct sockaddr_in broadcast = {
	.sin_family = AF_INET,
	.sin_addr = {INADDR_BROADCAST},
};

uint8_t recv_buffer[RECV_BUF_LEN];
uint8_t send_buffer[SEND_BUF_LEN];

struct config cfg = CONFIG_EMPTY;

bool debug = false;

static const char BROKEN_SOFTWARE_NOTIFICATION[] = 
"#################################### ALERT ####################################\n"
"  BROKEN SOFTWARE NOTIFICATION - SOMETHING SENDS INVALID DHCP MESSAGES IN YOUR\n"
"                                    NETWORK\n";

#define MAC_ADDRSTRLEN 18

/* This function converts a L2 MAC address in binary format to a text format */
static int mac_ntop(char *addr, char *dst, size_t s)
{
	return snprintf(dst, s,
		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", 
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* Return netmask for specified prefix length */
static uint32_t netmask_from_prefixlen(uint8_t prefixlen)
{
	return htonl(0xFFFFFFFFU - (1 << (32 - prefixlen)) + 1);
}

static bool dump_iplist(struct in_addr *in, size_t in_cnt, char *out, size_t out_len)
{
	size_t n_len = INET_ADDRSTRLEN * in_cnt + in_cnt;
	memset(out, 0, n_len);
	if (n_len > out_len)
		return false;

	for (size_t i = 0; i < in_cnt; ++i)
	{
		inet_ntop(AF_INET, &in[i], out, INET_ADDRSTRLEN);

		while (*out)
			++out;

		*out = ',';
		++out;
	}

	*(out-1) = 0;
	//out[n_len-1] = 0;

	return true;
}

static bool parse_iplist(const char *in, struct in_addr **out, size_t *cnt)
{
	size_t off = 0;
	char addr[INET_ADDRSTRLEN];
	memset(addr, 0, INET_ADDRSTRLEN);
	while (*in && off < INET_ADDRSTRLEN-1)
	{
		addr[off++] = *(in++);

		if (*in == ',' || *in == 0)
		{
			*out = realloc(*out, sizeof **out * ++(*cnt));
			if (inet_pton(AF_INET, addr, &(*out)[(*cnt)-1]) == 0)
				goto return_false;

			off = 0;
			memset(addr, 0, INET_ADDRSTRLEN);

			if (*in != 0)
				++in;
		}
	}

	if (!(off < INET_ADDRSTRLEN-1))
	{
return_false:
		free(*out);
		*out = NULL;
		*cnt = 0;
		return false;
	}

	return true;
}

static void discover_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	int sqlerr, err;
	sqlite3_stmt *ldb_query;

	sqlerr = sqlite3_prepare_v2(leasedb,
		"SELECT address, routers, nameservers, prefixlen, leasetime "
		"FROM leases "
		"WHERE hwaddr = ?;", -1, &ldb_query, NULL);
	if (sqlerr != SQLITE_OK)
	{
		dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
		return;
	}

	sqlerr = sqlite3_bind_text(ldb_query, 1, msg->chaddr, -1, NULL);
	if (sqlerr != SQLITE_OK)
		goto sql_error;

	sqlerr = sqlite3_step(ldb_query);

	struct dhcp_lease lease = DHCP_LEASE_EMPTY;
	bool unalloc_lease = false;

	if (sqlerr != SQLITE_ROW)
	{
		if (sqlerr != SQLITE_DONE)
			goto sql_error;

		sqlite3_finalize(ldb_query);

		if (cfg.argv->allocate)
		{
			lease.routers = cfg.routers;
			lease.routers_cnt = cfg.routers_cnt;
			lease.nameservers = cfg.nameservers;
			lease.nameservers_cnt = cfg.nameservers_cnt;
			lease.leasetime = cfg.leasetime;
			lease.prefixlen = cfg.prefixlen;

			/* TODO optimize this */
			uint32_t iprange[2] = { ntohl(cfg.iprange[0].s_addr), ntohl(cfg.iprange[1].s_addr) };
			uint32_t ip;

			sqlite3_prepare_v2(leasedb,
				"SELECT COUNT(*) "
				"FROM leases "
				"WHERE address = ?;", -1, &ldb_query, NULL);

			for (ip = iprange[0]; ip <= iprange[1]; ++ip)
			{
				lease.address.s_addr = htonl(ip);
				char ip_str[INET_ADDRSTRLEN];

				inet_ntop(AF_INET, &lease.address, ip_str, INET_ADDRSTRLEN);
				sqlite3_bind_text(ldb_query, 1, ip_str, -1, NULL);

				if (sqlite3_step(ldb_query) == SQLITE_ERROR)
					goto sql_error;

				if (sqlite3_column_int(ldb_query, 0) == 0)
				{
					sqlite3_finalize(ldb_query);
					goto offer;
				}

				sqlite3_reset(ldb_query);
			}

			sqlite3_finalize(ldb_query);
		}
		return;
	}
	else
	{
		struct db_lease db_lease = DB_LEASE_EMPTY;

		db_lease.address = (char*)sqlite3_column_text(ldb_query, 0);
		db_lease.routers = (char*)sqlite3_column_text(ldb_query, 1);
		db_lease.nameservers = (char*)sqlite3_column_text(ldb_query, 2);
		db_lease.prefixlen = sqlite3_column_int(ldb_query, 3);
		db_lease.leasetime = sqlite3_column_int(ldb_query, 4);

		if (db_lease.address == NULL)
			goto invalid_lease_entry;

		lease.leasetime = db_lease.leasetime;
		lease.prefixlen = db_lease.prefixlen;

		unalloc_lease = true;

		if (!inet_pton(AF_INET, db_lease.address, &lease.address))
			goto invalid_lease_entry;

		if (db_lease.routers)
			if (!parse_iplist(db_lease.routers, &lease.routers, &lease.routers_cnt))
				goto invalid_lease_entry;

		if (db_lease.nameservers)
			if (!parse_iplist(db_lease.nameservers, &lease.nameservers, &lease.nameservers_cnt))
				goto invalid_lease_entry;

		if (0)
		{
invalid_lease_entry:
			if (lease.routers)
				free(lease.routers);
			if (lease.nameservers)
				free(lease.nameservers);

			fprintf(stderr, "Invalid lease entry for %s:\n"
					"\tAddress: %s\n"
					"\tRouters: %s\n"
					"\tNameservers: %s\n"
					"\tPrefix Length: %hhu\n"
					"\tLease Time: %u\n",
					msg->chaddr,
					db_lease.address,
					db_lease.routers,
					db_lease.nameservers,
					db_lease.prefixlen,
					db_lease.leasetime);
			sqlite3_finalize(ldb_query);
			return;
		}

		sqlite3_finalize(ldb_query);
	}

	size_t send_len;
offer:
	send_len = DHCP_MSG_HDRLEN;
	memset(send_buffer, 0, DHCP_MSG_LEN);
	dhcp_msg_prepare(send_buffer, msg->data);

	ARRAY_COPY(DHCP_MSG_F_SIADDR(send_buffer), &server_id.sin_addr, 4);

	*((struct in_addr *)DHCP_MSG_F_YIADDR(send_buffer)) = lease.address;

	uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);

	options[0] = DHCP_OPT_MSGTYPE;
	options[1] = 1;
	options[2] = DHCPOFFER;
	DHCP_OPT_CONT(options, send_len);

	options[0] = DHCP_OPT_NETMASK;
	options[1] = 4;
	ARRAY_COPY((options + 2), (uint8_t*)((uint32_t[]){netmask_from_prefixlen(lease.prefixlen)}), 4);
	DHCP_OPT_CONT(options, send_len);

	if (lease.routers_cnt > 0)
	{
		options[0] = DHCP_OPT_ROUTER;
		options[1] = lease.routers_cnt * 4;
		for (size_t i = 0; i < lease.routers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease.routers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	options[0] = DHCP_OPT_SERVERID;
	options[1] = 4;
	ARRAY_COPY((options + 2), &server_id.sin_addr, 4);
	DHCP_OPT_CONT(options, send_len);

	options[0] = DHCP_OPT_LEASETIME;
	options[1] = 4;
	*(uint32_t*)(options + 2) = htonl(lease.leasetime);
	DHCP_OPT_CONT(options, send_len);

	if (lease.nameservers_cnt > 0)
	{
		options[0] = DHCP_OPT_DNS;
		options[1] = 4 * lease.nameservers_cnt;
		for (size_t i = 0; i < lease.nameservers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease.nameservers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	*options = DHCP_OPT_END;
	DHCP_OPT_CONT(options, send_len);

	err = sendto(w->fd,
		send_buffer, send_len,
		MSG_DONTWAIT, (struct sockaddr *)&broadcast, sizeof broadcast);

	if (err < 0)
		dhcpd_error(0, 1, "Could not send DHCPOFFER");

	if (unalloc_lease)
	{
		if (lease.routers)
			free(lease.routers);
		if (lease.nameservers)
			free(lease.nameservers);
	}

	return;
sql_error:

	dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
	sqlite3_finalize(ldb_query);
}

static void request_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	struct in_addr *requested_addr, *requested_server;
	uint8_t *options;
	struct dhcp_opt current_opt;

	requested_addr = NULL;
	requested_server = (struct in_addr *)DHCP_MSG_F_SIADDR(msg->data);
	options = DHCP_MSG_F_OPTIONS(msg->data);

	while (dhcp_opt_next(&options, &current_opt, msg->end))
		switch (current_opt.code)
		{
			case 50:
				requested_addr = (struct in_addr *)current_opt.data;
				break;
			case 54:
				requested_server = (struct in_addr *)current_opt.data;
				break;
		}

	if (requested_server->s_addr != server_id.sin_addr.s_addr)
		return;

	int sqlerr, err;
	sqlite3_stmt *ldb_query;

	sqlerr = sqlite3_prepare_v2(leasedb,
		"SELECT address, routers, nameservers, prefixlen, leasetime "
		"FROM leases "
		"WHERE hwaddr = ?;", -1, &ldb_query, NULL);
	if (sqlerr != SQLITE_OK)
	{
		dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
		return;
	}

	sqlerr = sqlite3_bind_text(ldb_query, 1, msg->chaddr, -1, NULL);
	if (sqlerr != SQLITE_OK)
		goto sql_error;

	sqlerr = sqlite3_step(ldb_query);

	struct dhcp_lease lease = DHCP_LEASE_EMPTY;
	bool unalloc_lease = false;

	if (sqlerr != SQLITE_ROW)
	{
		if (sqlerr != SQLITE_DONE)
			goto sql_error;

		sqlite3_finalize(ldb_query);

		if (cfg.argv->allocate)
		{
			if (ntohl(cfg.iprange[0].s_addr) <= ntohl(requested_addr->s_addr) &&
					ntohl(cfg.iprange[1].s_addr) >= ntohl(requested_addr->s_addr))
			{
				sqlerr = sqlite3_prepare_v2(leasedb,
					"INSERT INTO leases "
					"('address', 'routers', 'nameservers', 'prefixlen', 'leasetime', "
					"'allocated', 'hwaddr') VALUES "
					"(?, ?, ?, ?, ?, ?, ?);", -1, &ldb_query, NULL);
				if (sqlerr != SQLITE_OK)
				{
					dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
					goto nack;
				}

				lease.address = *requested_addr;
				lease.routers = cfg.routers;
				lease.routers_cnt = cfg.routers_cnt;
				lease.nameservers = cfg.nameservers;
				lease.nameservers_cnt = cfg.nameservers_cnt;
				lease.leasetime = cfg.leasetime;
				lease.prefixlen = cfg.prefixlen;

				char routers[INET_ADDRSTRLEN * lease.routers_cnt + lease.routers_cnt];
				dump_iplist(lease.routers, lease.routers_cnt, routers, ARRAY_LEN(routers));
				char nameservers[INET_ADDRSTRLEN * lease.nameservers_cnt + lease.nameservers_cnt];
				dump_iplist(lease.nameservers, lease.nameservers_cnt, nameservers, ARRAY_LEN(nameservers));
				char address[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &lease.address, address, INET_ADDRSTRLEN);
				
				sqlerr = sqlite3_bind_text(ldb_query, 1, address, -1, NULL);
				sqlerr = sqlite3_bind_text(ldb_query, 2, routers, -1, NULL);
				sqlerr = sqlite3_bind_text(ldb_query, 3, nameservers, -1, NULL);
				sqlerr = sqlite3_bind_int(ldb_query, 4, lease.prefixlen);
				sqlerr = sqlite3_bind_int(ldb_query, 5, lease.leasetime);
				sqlerr = sqlite3_bind_int(ldb_query, 6, 1);
				sqlerr = sqlite3_bind_text(ldb_query, 7, msg->chaddr, -1, NULL);

				sqlerr = sqlite3_step(ldb_query);
				if (sqlerr != SQLITE_DONE)
				{
					dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
					sqlite3_finalize(ldb_query);
					goto nack;
				}

				sqlite3_finalize(ldb_query);

				goto ack;
			}
		}

		goto nack;
	}
	else
	{
		struct db_lease db_lease = DB_LEASE_EMPTY;

		db_lease.address = (char*)sqlite3_column_text(ldb_query, 0);
		db_lease.routers = (char*)sqlite3_column_text(ldb_query, 1);
		db_lease.nameservers = (char*)sqlite3_column_text(ldb_query, 2);
		db_lease.prefixlen = sqlite3_column_int(ldb_query, 3);
		db_lease.leasetime = sqlite3_column_int(ldb_query, 4);

		if (db_lease.address == NULL)
			goto invalid_lease_entry;

		lease.leasetime = db_lease.leasetime;
		lease.prefixlen = db_lease.prefixlen;

		unalloc_lease = true;

		if (!inet_pton(AF_INET, db_lease.address, &lease.address))
			goto invalid_lease_entry;

		if (db_lease.routers)
			if (!parse_iplist(db_lease.routers, &lease.routers, &lease.routers_cnt))
				goto invalid_lease_entry;

		if (db_lease.nameservers)
			if (!parse_iplist(db_lease.nameservers, &lease.nameservers, &lease.nameservers_cnt))
				goto invalid_lease_entry;

		if (0)
		{
invalid_lease_entry:
			if (lease.nameservers)
				free(lease.nameservers);
			if (lease.routers)
				free(lease.routers);

			fprintf(stderr, "Invalid lease entry for %s:\n"
					"\tAddress: %s\n"
					"\tRouters: %s\n"
					"\tNameservers: %s\n"
					"\tPrefix Length: %hhu\n"
					"\tLease Time: %u\n",
					msg->chaddr,
					db_lease.address,
					db_lease.routers,
					db_lease.nameservers,
					db_lease.prefixlen,
					db_lease.leasetime);
			sqlite3_finalize(ldb_query);
			goto nack;
		}
	}

	sqlite3_finalize(ldb_query);

	if (memcmp(&lease.address, requested_addr, 4) != 0)
	{
		if (lease.nameservers)
			free(lease.nameservers);
		if (lease.routers)
			free(lease.routers);

		size_t send_len;
nack:
		send_len = DHCP_MSG_HDRLEN;
		memset(send_buffer, 0, DHCP_MSG_LEN);
		dhcp_msg_prepare(send_buffer, msg->data);

		ARRAY_COPY(DHCP_MSG_F_SIADDR(send_buffer), &server_id.sin_addr, 4);

		uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);

		options[0] = DHCP_OPT_MSGTYPE;
		options[1] = 1;
		options[2] = DHCPNAK;
		DHCP_OPT_CONT(options, send_len);

		options[0] = DHCP_OPT_END;
		DHCP_OPT_CONT(options, send_len);

		err = sendto(w->fd,
			send_buffer, send_len,
			MSG_DONTWAIT, (struct sockaddr *)&broadcast, sizeof broadcast);

		if (err < 0)
			dhcpd_error(0, 1, "Could not send DHCPNAK");
		
		return;
	}

	size_t send_len;
ack:
	send_len = DHCP_MSG_HDRLEN;
	memset(send_buffer, 0, DHCP_MSG_LEN);
	dhcp_msg_prepare(send_buffer, msg->data);

	ARRAY_COPY(DHCP_MSG_F_SIADDR(send_buffer), &server_id.sin_addr, 4);

	*((struct in_addr *)DHCP_MSG_F_YIADDR(send_buffer)) = lease.address;

	options = DHCP_MSG_F_OPTIONS(send_buffer);

	options[0] = DHCP_OPT_MSGTYPE;
	options[1] = 1;
	options[2] = DHCPACK;
	DHCP_OPT_CONT(options, send_len);

	options[0] = DHCP_OPT_NETMASK;
	options[1] = 4;
	ARRAY_COPY((options + 2), (uint8_t*)((uint32_t[]){netmask_from_prefixlen(lease.prefixlen)}), 4);
	DHCP_OPT_CONT(options, send_len);

	if (lease.routers_cnt > 0)
	{
		options[0] = DHCP_OPT_ROUTER;
		options[1] = lease.routers_cnt * 4;
		for (size_t i = 0; i < lease.routers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease.routers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	options[0] = DHCP_OPT_SERVERID;
	options[1] = 4;
	ARRAY_COPY((options + 2), &server_id.sin_addr, 4);
	DHCP_OPT_CONT(options, send_len);

	options[0] = DHCP_OPT_LEASETIME;
	options[1] = 4;
	*(uint32_t*)(options + 2) = htonl(lease.leasetime);
	DHCP_OPT_CONT(options, send_len);

	if (lease.nameservers_cnt > 0)
	{
		options[0] = DHCP_OPT_DNS;
		options[1] = lease.nameservers_cnt * 4;
		for (size_t i = 0; i < lease.nameservers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease.nameservers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	*options = DHCP_OPT_END;
	DHCP_OPT_CONT(options, send_len);

	err = sendto(w->fd,
		send_buffer, send_len,
		MSG_DONTWAIT, (struct sockaddr *)&broadcast, sizeof broadcast);

	if (err < 0)
		dhcpd_error(0, 1, "Could not send DHCPACK");

	if (unalloc_lease)
	{
		if (lease.routers)
			free(lease.routers);
		if (lease.nameservers)
			free(lease.nameservers);
	}

	return;
sql_error:

	dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
	sqlite3_finalize(ldb_query);
}

static void release_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
}

static void decline_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
}

static void inform_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
}

static void req_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_in src_addr;
	socklen_t src_addrlen = AF_INET;

	/* Receive data from socket */
	ssize_t recvd = recvfrom(
		w->fd,
		recv_buffer,
		RECV_BUF_LEN,
		MSG_DONTWAIT,
		(struct sockaddr * restrict)&src_addr, &src_addrlen);

	/* Detect errors */
	if (recvd < 0)
		return;
	/* Detect too small messages */
	if (recvd < 241)
		return;
	/* Check magic value */
	uint8_t *magic = DHCP_MSG_F_MAGIC(recv_buffer);
	if (!DHCP_MSG_MAGIC_CHECK(magic))
		return;

	/* Convert addresses to strings */
	char ciaddr[INET_ADDRSTRLEN],
			 yiaddr[INET_ADDRSTRLEN],
			 siaddr[INET_ADDRSTRLEN],
			 giaddr[INET_ADDRSTRLEN],
			 chaddr[MAC_ADDRSTRLEN],
			 srcaddr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, DHCP_MSG_F_CIADDR(recv_buffer), ciaddr, sizeof ciaddr);
	inet_ntop(AF_INET, DHCP_MSG_F_YIADDR(recv_buffer), yiaddr, sizeof yiaddr);
	inet_ntop(AF_INET, DHCP_MSG_F_SIADDR(recv_buffer), siaddr, sizeof siaddr);
	inet_ntop(AF_INET, DHCP_MSG_F_GIADDR(recv_buffer), giaddr, sizeof giaddr);
	inet_ntop(AF_INET, &src_addr.sin_addr, srcaddr, sizeof srcaddr);
	mac_ntop(DHCP_MSG_F_CHADDR(recv_buffer), chaddr, sizeof chaddr);

	/* Extract message type from options */
	uint8_t *options = DHCP_MSG_F_OPTIONS(recv_buffer);
	struct dhcp_opt current_option;

	enum dhcp_msg_type msg_type = 0;

	while (dhcp_opt_next(&options, &current_option, (uint8_t*)(recv_buffer + recvd)))
		if (current_option.code == 53)
			msg_type = (enum dhcp_msg_type)current_option.data[0];

	struct dhcp_msg msg = {
		.data = recv_buffer,
		.end = recv_buffer + recvd,
		.length = recvd,
		.type = msg_type,
		.ciaddr = ciaddr,
		.yiaddr = yiaddr,
		.siaddr = siaddr,
		.giaddr = giaddr,
		.chaddr = chaddr,
		.srcaddr = srcaddr,
		.source = (struct sockaddr *)&src_addr
	};

	if (debug)
		dhcp_msg_dump(stderr, &msg);

	switch (msg_type)
	{
		case DHCPDISCOVER:
			discover_cb(EV_A_ w, &msg);
			break;

		case DHCPREQUEST:
			request_cb(EV_A_ w, &msg);
			break;

		case DHCPRELEASE:
			release_cb(EV_A_ w, &msg);
			break;

		case DHCPDECLINE:
			decline_cb(EV_A_ w, &msg);
			break;

		case DHCPINFORM:
			inform_cb(EV_A_ w, &msg);
			break;

		default:
			fprintf(stderr, BROKEN_SOFTWARE_NOTIFICATION);
			break;
	}
}

static void sigint_cb(EV_P_ ev_signal *sig, int revents)
{
	ev_break(EV_A_ EVBREAK_ALL);
}

int main(int argc, char **argv)
{
	struct argv argv_cfg = ARGV_EMPTY;

	if (!argv_parse(argc, argv, &argv_cfg))
	{
		if (argv_cfg.argerror == -1)
			dhcpd_error(1, 0, "Unexpected argument list end");
		else
			dhcpd_error(1, 0, "Unexpected argument %s", argv_cfg.argv[argv_cfg.argerror]);
		exit(1);
	}

	if (argv_cfg.help || argv_cfg.interface == NULL)
	{
		printf("%s [-help] [-version] [-debug] [-user UID] [-group GID]\n"
			"\t[-interface IF] [-db FILE]\n"
			"\t[-allocate] [-iprange IP IP] [-router IP]... [-nameserver IP]...\n",
			argv_cfg.arg0);
		exit(0);
	}

	if (!config_fill(&cfg, &argv_cfg))
		dhcpd_error(1, 0, cfg.error);

	if (argv_cfg.user != NULL)
	{
#ifdef __linux__
		uid_t uid = 0;
		gid_t gid = 0;

		struct passwd *pwent;

		pwent = getpwnam(argv_cfg.user);
		if (pwent == NULL)
		{
			pwent = getpwuid(atoi(argv_cfg.user));
			if (pwent == NULL)
				dhcpd_error(1, errno, "Could not find user identified by \"%s\"", argv_cfg.user);
		}

		uid = pwent->pw_uid;
		gid = pwent->pw_gid;

		if (argv_cfg.group != NULL)
		{
			struct group *grent;
			
			grent = getgrnam(argv_cfg.group);
			if (grent == NULL)
			{
				grent = getgrgid(atoi(argv_cfg.group));
				if (grent == NULL)
					dhcpd_error(1, errno, "Could not find user identified by \"%s\"", argv_cfg.group);
			}

			gid = grent->gr_gid;
		}

		prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

		setgid(gid);
		setuid(uid);

		cap_t caps;
		caps = cap_init();

		cap_value_t cap_flags[] = {
			CAP_NET_BIND_SERVICE,
			CAP_NET_BROADCAST,
			CAP_NET_RAW
		};

		cap_set_flag(caps, CAP_EFFECTIVE, ARRAY_LEN(cap_flags), cap_flags, CAP_SET);
		cap_set_flag(caps, CAP_PERMITTED, ARRAY_LEN(cap_flags), cap_flags, CAP_SET);

		cap_set_proc(caps);

		cap_free(caps);
#else
		dhcpd_error(1, 0, "Can only drop privileges on Linux");
#endif
	}

	/* Set client IP address */
	broadcast.sin_port = htons(68);
	/* Clear IO buffers */
	memset(send_buffer, 0, ARRAY_LEN(send_buffer));
	memset(recv_buffer, 0, ARRAY_LEN(recv_buffer));

	if (argv_cfg._new && !argv_cfg.allocate)
		dhcpd_error(0, 0, "Hint: -new doesn't make any sense without -allocate");

	if (if_nametoindex(argv_cfg.interface) == 0)
		dhcpd_error(1, errno, argv_cfg.interface);

	bool alloc_db = false;

	if (argv_cfg.db == NULL)
	{
		size_t len = strlen(argv_cfg.interface) + sizeof(".db") + 1;
		argv_cfg.db = malloc(len);
		stpcpy(stpcpy(argv_cfg.db, argv_cfg.interface), ".db");
		argv_cfg.db[len-1] = 0;
		alloc_db = true;
	}

	if (argv_cfg.debug)
		debug = true;

	if (sqlite3_open(argv_cfg.db, &leasedb) != SQLITE_OK)
		dhcpd_error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(leasedb));

	if (argv_cfg._new)
		db_init(leasedb);

	int sock;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		dhcpd_error(1, errno, "Could not create socket");

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(67),
		.sin_addr = {INADDR_ANY}
	};

	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) == -1)
		dhcpd_error(1, errno, "Could not get interface information");

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in *ifa_addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			server_id = *ifa_addr_in;
		}
	}

	freeifaddrs(ifaddrs);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set socket to reuse address");

	if (bind(sock, (const struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) < 0)
		dhcpd_error(1, errno, "Could not bind to 0.0.0.0:67");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set broadcast socket option");
#ifdef __linux__
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, argv_cfg.interface, strlen(argv_cfg.interface)) != 0)
		dhcpd_error(1, errno, "Could not bind to device %s", argv_cfg.interface);
#endif

	struct ev_loop *loop = EV_DEFAULT;

	ev_io read_watch;
	ev_signal sigint_watch;

	ev_io_init(&read_watch, req_cb, sock, EV_READ);
	ev_io_start(loop, &read_watch);

	ev_signal_init(&sigint_watch, sigint_cb, SIGINT);
	ev_signal_start(loop, &sigint_watch);

	ev_run(loop, 0);

	if (sqlite3_close(leasedb) != SQLITE_OK)
	{
		dhcpd_error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
	}

	config_free(&cfg);
	argv_free(&argv_cfg);
	if (alloc_db)
		free(argv_cfg.db);

	exit(0);
}

