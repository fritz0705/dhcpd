/* (c) 2013 Fritz Conrad Grimpen */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <ev.h>
#include <sqlite3.h>

#include "dhcp.h"

#define RECV_BUF_LEN 4096
#define SEND_BUF_LEN 4096

#define COPY_ARRAY(dst, src, len) { \
		struct { \
			uint8_t _[len]; \
		} *_src, *_dst; \
		_src = (void*)src; \
		_dst = (void*)dst; \
		*_dst = *_src; \
	}

sqlite3 *leasedb;

struct sockaddr_in server_id;

char recv_buffer[RECV_BUF_LEN];
char send_buffer[SEND_BUF_LEN];

bool debug = true;

#define MAC_ADDRSTRLEN 18

static int mac_ntop(char *addr, char *dst, size_t s)
{
	return snprintf(dst, s,
		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", 
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void discover_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	int sqlerr, err;
	sqlite3_stmt *ldb_query;

	sqlerr = sqlite3_prepare_v2(leasedb,
		"SELECT address, routers, nameservers, prefixlen "
		"FROM leases "
		"WHERE hwaddr = ?;", -1, &ldb_query, NULL);
	if (sqlerr != SQLITE_OK)
		goto failure;

	sqlerr = sqlite3_bind_text(ldb_query, 1, msg->chaddr, -1, NULL);
	if (sqlerr != SQLITE_OK)
		goto failure;

	sqlerr = sqlite3_step(ldb_query);
	if (sqlerr != SQLITE_ROW)
	{
		if (sqlerr != SQLITE_DONE)
			goto failure;
		goto finalize;
	}

	const unsigned char *l_address, *l_routers, *l_nameservers;
	int l_prefixlen;

	l_address = sqlite3_column_text(ldb_query, 0);
	l_routers = sqlite3_column_text(ldb_query, 1);
	l_nameservers = sqlite3_column_text(ldb_query, 2);
	l_prefixlen = sqlite3_column_int(ldb_query, 3);

	uint32_t subnetmask = 0xFFFFFFFFU - (1 << (32 - l_prefixlen)) + 1;
	subnetmask = htonl(subnetmask);

	size_t send_len = DHCP_MSG_HDRLEN;

	memset(send_buffer, 0, DHCP_MSG_LEN);
	*DHCP_MSG_F_XID(send_buffer) = *DHCP_MSG_F_XID(msg->data);
	*DHCP_MSG_F_HTYPE(send_buffer) = *DHCP_MSG_F_HTYPE(msg->data);
	*DHCP_MSG_F_HLEN(send_buffer) = *DHCP_MSG_F_HLEN(msg->data);
	*DHCP_MSG_F_OP(send_buffer) = 2;
	COPY_ARRAY(DHCP_MSG_F_SIADDR(send_buffer), &server_id.sin_addr, 4);
	COPY_ARRAY(DHCP_MSG_F_MAGIC(send_buffer), DHCP_MSG_MAGIC, 4);
	COPY_ARRAY(DHCP_MSG_F_CHADDR(send_buffer), DHCP_MSG_F_CHADDR(msg->data), 16);

	uint8_t *magic = DHCP_MSG_F_MAGIC(send_buffer);
	printf("[%u %u %u %u]\n", magic[0], magic[1], magic[2], magic[3]);

	if (!DHCP_MSG_MAGIC_CHECK(DHCP_MSG_F_MAGIC(send_buffer)))
		return;

	inet_pton(AF_INET, (const char *)l_address, DHCP_MSG_F_YIADDR(send_buffer));

	uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);

	options[0] = 53;
	options[1] = 1;
	options[2] = DHCPOFFER;
	options = DHCP_OPT_NEXT(options);
	send_len += 3;

	options[0] = 1;
	options[1] = 4;
	COPY_ARRAY((options + 2), (uint8_t*)&subnetmask, 4);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 3;
	options[1] = 4;
	inet_pton(AF_INET, (const char *)l_routers, options + 2);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 54;
	options[1] = 4;
	COPY_ARRAY((options + 2), &server_id.sin_addr, 4);
	send_len += 6;

	options[0] = 51;
	options[1] = 4;
	options[2] = 0xff;
	options[3] = 0xff;
	options[4] = 0xff;
	options[5] = 0xff;
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 6;
	options[1] = 4;
	inet_pton(AF_INET, (const char *)l_nameservers, options + 2);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	*options = 255;
	options = DHCP_OPT_NEXT(options);
	send_len += 1;

	struct sockaddr_in rcpt_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(68),
		.sin_addr = {INADDR_BROADCAST},
	};

	err = sendto(w->fd, send_buffer, send_len, MSG_DONTWAIT, (struct sockaddr *)&rcpt_addr, sizeof rcpt_addr);

finalize:
	sqlite3_finalize(ldb_query);
	return;

failure:
	error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
	sqlite3_finalize(ldb_query);
	return;
}

static void request_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	int sqlerr, err;
	sqlite3_stmt *ldb_query;

	sqlerr = sqlite3_prepare_v2(leasedb,
		"SELECT address, routers, nameservers, prefixlen "
		"FROM leases "
		"WHERE hwaddr = ?;", -1, &ldb_query, NULL);
	if (sqlerr != SQLITE_OK)
		goto failure;

	sqlerr = sqlite3_bind_text(ldb_query, 1, msg->chaddr, -1, NULL);
	if (sqlerr != SQLITE_OK)
		goto failure;

	sqlerr = sqlite3_step(ldb_query);
	if (sqlerr != SQLITE_ROW)
	{
		if (sqlerr != SQLITE_DONE)
			goto failure;
		goto finalize;
	}

	const unsigned char *l_address, *l_routers, *l_nameservers;
	int l_prefixlen;

	l_address = sqlite3_column_text(ldb_query, 0);
	l_routers = sqlite3_column_text(ldb_query, 1);
	l_nameservers = sqlite3_column_text(ldb_query, 2);
	l_prefixlen = sqlite3_column_int(ldb_query, 3);

	uint32_t subnetmask = 0xFFFFFFFFU - (1 << (32 - l_prefixlen)) + 1;
	subnetmask = htonl(subnetmask);

	size_t send_len = DHCP_MSG_HDRLEN;

	memset(send_buffer, 0, DHCP_MSG_LEN);
	*DHCP_MSG_F_XID(send_buffer) = *DHCP_MSG_F_XID(msg->data);
	*DHCP_MSG_F_HTYPE(send_buffer) = *DHCP_MSG_F_HTYPE(msg->data);
	*DHCP_MSG_F_HLEN(send_buffer) = *DHCP_MSG_F_HLEN(msg->data);
	*DHCP_MSG_F_OP(send_buffer) = 2;
	COPY_ARRAY(DHCP_MSG_F_SIADDR(send_buffer), &server_id.sin_addr, 4);
	COPY_ARRAY(DHCP_MSG_F_MAGIC(send_buffer), DHCP_MSG_MAGIC, 4);
	COPY_ARRAY(DHCP_MSG_F_CHADDR(send_buffer), DHCP_MSG_F_CHADDR(msg->data), 16);

	if (!DHCP_MSG_MAGIC_CHECK(DHCP_MSG_F_MAGIC(send_buffer)))
		return;

	inet_pton(AF_INET, (const char *)l_address, DHCP_MSG_F_YIADDR(send_buffer));

	uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);

	options[0] = 53;
	options[1] = 1;
	options[2] = DHCPACK;
	options = DHCP_OPT_NEXT(options);
	send_len += 3;

	options[0] = 1;
	options[1] = 4;
	COPY_ARRAY((options + 2), (uint8_t*)&subnetmask, 4);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 3;
	options[1] = 4;
	inet_pton(AF_INET, (const char *)l_routers, options + 2);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 54;
	options[1] = 4;
	COPY_ARRAY((options + 2), &server_id.sin_addr, 4);
	send_len += 6;

	options[0] = 51;
	options[1] = 4;
	options[2] = 0xff;
	options[3] = 0xff;
	options[4] = 0xff;
	options[5] = 0xff;
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	options[0] = 6;
	options[1] = 4;
	inet_pton(AF_INET, (const char *)l_nameservers, options + 2);
	options = DHCP_OPT_NEXT(options);
	send_len += 6;

	*options = 255;
	options = DHCP_OPT_NEXT(options);
	send_len += 1;

	struct sockaddr_in rcpt_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(68),
		.sin_addr = {INADDR_BROADCAST},
	};

	err = sendto(w->fd, send_buffer, send_len, MSG_DONTWAIT, (struct sockaddr *)&rcpt_addr, sizeof rcpt_addr);

finalize:
	sqlite3_finalize(ldb_query);
	return;

failure:
	error(0, 0, "sqlite3: %s", sqlite3_errmsg(leasedb));
	sqlite3_finalize(ldb_query);
	return;
}

static void release_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
}

static void req_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_in src_addr;
	socklen_t src_addrlen;

	ssize_t recvd = recvfrom(
		w->fd,
		recv_buffer,
		RECV_BUF_LEN,
		MSG_DONTWAIT,
		(struct sockaddr * restrict)&src_addr, &src_addrlen);

	if (recvd < 0)
		return;
	if (recvd < 241)
		return;
	uint8_t *magic = DHCP_MSG_F_MAGIC(recv_buffer);
	if (!DHCP_MSG_MAGIC_CHECK(magic))
		return;

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

	uint8_t *options = DHCP_MSG_F_OPTIONS(recv_buffer);
	struct dhcp_opt current_option;

	enum dhcp_msg_type msg_type = 0;

	while (dhcp_opt_next(&options, &current_option, (uint8_t*)(recv_buffer + recvd)))
		if (current_option.code == 53)
			msg_type = (enum dhcp_msg_type)current_option.data[0];

	if (debug)
		fprintf(stderr,
			"DHCP message from %s:\n"
			"\tOP %hhu [%s]\n"
			"\tHTYPE %hhu HLEN %hhu\n"
			"\tHOPS %hhu\n"
			"\tXID %X\n"
			"\tSECS %hu FLAGS %hu\n"
			"\tCIADDR %s YIADDR %s SIADDR %s GIADDR %s\n"
			"\tCHADDR %s\n"
			"\tMAGIC %X\n"
			"\tMSG TYPE %u\n",
			srcaddr,
			*DHCP_MSG_F_OP(recv_buffer),
			(*DHCP_MSG_F_OP(recv_buffer) == 1 ? "REQUEST" : "REPLY"),
			*DHCP_MSG_F_HTYPE(recv_buffer),
			*DHCP_MSG_F_HLEN(recv_buffer),
			*DHCP_MSG_F_HOPS(recv_buffer),
			*DHCP_MSG_F_XID(recv_buffer),
			*DHCP_MSG_F_SECS(recv_buffer),
			*DHCP_MSG_F_FLAGS(recv_buffer),
			ciaddr, yiaddr, siaddr, giaddr,
			chaddr,
			*DHCP_MSG_F_MAGIC(recv_buffer),
			msg_type);

	struct dhcp_msg msg = {
		.data = recv_buffer,
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

		default:
			fprintf(stderr,
				"#################################### ALERT ####################################"
				"  BROKEN SOFTWARE NOTIFICATION - SOMETHING SENDS INVALID DHCP MESSAGES IN YOUR"
				"                                    NETWORK");
			break;
	}
}

int main(int argc, char **argv)
{
	if (argc != 2)
		error(1, 0, "Usage: dhcpd INTERFACE");

	char *if_name = argv[1];
	unsigned int interface = if_nametoindex(if_name);
	if (interface == 0)
		error(1, errno, if_name);

	char db_file[strlen(if_name) + sizeof(".db") + 1];
	stpcpy(stpcpy(db_file, if_name), ".db");
	db_file[-1] = 0;

	if (sqlite3_open(db_file, &leasedb) != SQLITE_OK)
		error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(leasedb));

	int sock;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		error(1, errno, "Could not create socket");

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(67),
		.sin_addr = {INADDR_ANY}
	};

	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) == -1)
		error(1, errno, "Could not get interface information");

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

	if (bind(sock, (const struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) < 0)
		error(1, errno, "Could not bind to 0.0.0.0:67");

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int)) != 0)
		error(1, errno, "Could not set broadcast socket option");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) != 0)
		error(1, errno, "Could not bind to device %s", if_name);

	struct ev_loop *loop = EV_DEFAULT;

	ev_io read_watch;

	ev_io_init(&read_watch, req_cb, sock, EV_READ);
	ev_io_start(loop, &read_watch);

	ev_run(loop, 0);
}

