/* (c) 2013 Fritz Conrad Grimpen */

#define DHCP_DHCPD

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#ifdef __linux__
#include <cap-ng.h>
#endif

#include <pwd.h>
#include <grp.h>

#include <ev.h>
#include <lmdb.h>
#include <jansson.h>

#include "dhcp.h"
#include "argv.h"
#include "error.h"
#include "config.h"

#ifndef RECV_BUF_LEN
#define RECV_BUF_LEN 4096
#endif

#ifndef SEND_BUF_LEN
#define SEND_BUF_LEN 4096
#endif

struct sockaddr_in server_id;
struct sockaddr_in broadcast = {
	.sin_family = AF_INET,
	.sin_addr = {INADDR_BROADCAST},
};

uint8_t recv_buffer[RECV_BUF_LEN];
uint8_t send_buffer[SEND_BUF_LEN];

struct config cfg = CONFIG_INIT;

json_t *template;

MDB_env *menv = NULL;

bool debug = false;

static const char USAGE[] =
"%s [-h[elp]] [-v[ersion]] [-user UID] [-group GID] [-interface IF] [-db FILE]\n"
"\t[-template KEY] [-range IP IP] [-include FILE]\n";

#define BROKEN_SOFTWARE_NOTIFICATION "\n"
#define MAC_ADDRSTRLEN 18

#define VERSION "1.0.0-lmdb"

/**
 * Convert MAC address from binary representation to text representation
 *
 * @param[in] addr Binary representation
 * @param[out] dst Buffer to write text presentation
 * @param[in] s Size of dst
 */
static int mac_ntop(char *addr, char *dst, size_t s)
{
	return snprintf(dst, s,
		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", 
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/**
 * Print debugging information with preamble marking incoming and
 * outgoing packets
 *
 * @param[in] msg Message to dump
 * @param[in] dir Direction of traffic, 0 for incoming and 1 for outgoing
 */
static void msg_debug(struct dhcp_msg *msg, int dir)
{
	if (dir == 0)
		fprintf(stderr, "--- INCOMING ---\n");
	else if (dir == 1)
		fprintf(stderr, "--- OUTGOING ---\n");

	dhcp_msg_dump(stderr, msg);
}

/**
 * Handle DHCPDISCOVER request and reply to that
 */
static void discover_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

/**
 * Handle to DHCPREQUEST request and reply to that, and allocate lease if
 * enabled
 */
static void request_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

/**
 * Handle DHCPRELEASE request and release the lease if it was allocated
 */
static void release_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

/**
 * Handle DHCPDECLINE request and do nothing at the moment
 */
static void decline_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

/**
 * Handle DHCPINFORM request and reply with the correct information
 */
static void inform_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

/**
 * Handle libev IO event to socket and call the correct message type
 * handler.
 */
static void req_cb(EV_P_ ev_io *w, int revents)
{
	(void)revents;

	/* Initialize address struct passed to recvfrom */
	struct sockaddr_in src_addr = {
		.sin_addr = {INADDR_ANY}
	};
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
	if (recvd < DHCP_MSG_HDRLEN)
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
		.source = (struct sockaddr *)&src_addr,
		.sid = (struct sockaddr_in *)&server_id
	};

	if (debug)
		msg_debug(&msg, 0);

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
			msg_debug(&msg, 0);
			break;
	}
}

/**
 * Break event loop to force a shutdown
 */
static void sigint_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;

	ev_break(EV_A_ EVBREAK_ALL);
}

/**
 * Commit current transaction
 */
static void sigusr1_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;
}

/**
 * Rollback current transaction
 */
static void sigusr2_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;
}

/**
 * Garbage collection for old leases
 */
static void leasegc_cb(EV_P_ ev_timer *timer, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)timer;
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

	if (argv_cfg.version)
	{
		printf("dhcpd " VERSION " - (c) 2013 Fritz Conrad Grimpen\n");
		exit(0);
	}

	if (argv_cfg.help || argv_cfg.interface == NULL)
	{
		printf(USAGE, argv_cfg.arg0);
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

		capng_clear(CAPNG_SELECT_BOTH);
		capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW, -1);
		if (capng_change_id(uid, gid, CAPNG_DROP_SUPP_GRP | CAPNG_CLEAR_BOUNDING))
			dhcpd_error(1, 0, "Could not change UID and drop capabilities");
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

	if (argv_cfg.db == NULL)
		argv_cfg.db = argv_cfg.interface;

	if (argv_cfg.debug)
		debug = true;

	int err = mdb_env_create(&menv);
	if (err != 0)
	{
	}

	err = mdb_env_open(menv, argv_cfg.db, 0, 0600);
	if (err != 0)
	{
	}

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

		if (ifa->ifa_addr->sa_family == AF_INET &&
				strcmp(ifa->ifa_name, argv_cfg.interface) == 0)
		{
			struct sockaddr_in *ifa_addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			server_id = *ifa_addr_in;
			break;
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
	ev_signal sigint_watch, sigusr1_watch, sigusr2_watch, sigterm_watch;
	ev_timer leasegc_watch;

	ev_io_init(&read_watch, req_cb, sock, EV_READ);
	ev_io_start(loop, &read_watch);

	ev_signal_init(&sigint_watch, sigint_cb, SIGINT);
	ev_signal_start(loop, &sigint_watch);

	ev_signal_init(&sigterm_watch, sigint_cb, SIGTERM);
	ev_signal_start(loop, &sigterm_watch);

	ev_signal_init(&sigusr1_watch, sigusr1_cb, SIGUSR1);
	ev_signal_start(loop, &sigusr1_watch);

	ev_signal_init(&sigusr2_watch, sigusr2_cb, SIGUSR2);
	ev_signal_start(loop, &sigusr2_watch);

	if (cfg.gc > 0)
	{
		ev_timer_init(&leasegc_watch, leasegc_cb, 0., cfg.gc);
		ev_timer_again(loop, &leasegc_watch);
	}
	
	ev_run(loop, 0);

	config_free(&cfg);
	argv_free(&argv_cfg);

	exit(0);
}

