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
#include "error.h"

#include "tools.h"

#ifndef RECV_BUF_LEN
#define RECV_BUF_LEN 4096
#endif

static struct sockaddr_in server_id;
static struct sockaddr_in broadcast = {
	.sin_family = AF_INET,
	.sin_addr = {INADDR_BROADCAST}
};

static json_t *config;

static bool debug = false;

static uint8_t recv_buffer[RECV_BUF_LEN];

static MDB_env *menv = NULL;

static const char USAGE[] =
"%s [-h[elp]] [-v[ersion]] [-user UID] [-group GID] [-interface IF] [-db FILE]\n"
"\t[-template KEY] [-range IP IP] [-include FILE]\n";

#define VERSION "1.0.0-lmdb"

static void msg_debug(struct dhcp_msg *msg, int dir)
{
	if (dir == 0)
		fprintf(stderr, "--- INCOMING ---\n");
	else if (dir == 1)
		fprintf(stderr, "--- OUTGOING ---\n");

	(void)msg;

	dhcp_msg_dumpf(msg, stderr);
}

static void discover_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

static void request_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

static void release_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

static void decline_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

static void inform_cb(EV_P_ ev_io *w, struct dhcp_msg *msg)
{
	(void)EV_A;
	(void)w;
	(void)msg;
}

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

	struct dhcp_msg msg = (struct dhcp_msg){
		.data = recv_buffer,
		.length = recvd,
		.type = 0,
		.source = (struct sockaddr *)&src_addr
	};

	/* Extract message type from options */
	uint8_t *options = DHCP_MSG_F_OPTIONS(recv_buffer);
	struct dhcp_opt current_option;

	while (dhcp_opt_next(&options, &current_option, (uint8_t*)(recv_buffer + recvd)))
		if (current_option.code == 53)
			msg.type = (enum dhcp_msg_type)current_option.data[0];

	switch (msg.type)
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
			if (!debug)
				msg_debug(&msg, 0);
		case DHCPOFFER:
		case DHCPACK:
		case DHCPNAK:
			break;
	}

	if (debug)
		msg_debug(&msg, 0);
}

static void sigint_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;

	ev_break(EV_A_ EVBREAK_ALL);
}

static void sigusr1_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;
}

static void sigusr2_cb(EV_P_ ev_signal *sig, int revents)
{
	(void)revents;
	(void)EV_A;
	(void)sig;
}

static bool drop_privileges(const char *user, const char *group, const char **error)
{
#ifdef __linux__
	uid_t uid = 0;
	gid_t gid = 0;
	
	struct passwd *pwent;

	pwent = getpwnam(user);
	if (!pwent)
	{
		pwent = getpwuid(atoi(user));
		if (!pwent)
		{
			if (error)
				*error = "Could not find given user to drop privileges";
			return false;
		}
	}

	uid = pwent->pw_uid;
	gid = pwent->pw_gid;

	if (group)
	{
		struct group *grent;

		grent = getgrnam(group);
		if (!grent)
		{
			grent = getgrgid(atoi(group));
			if (!grent)
			{
				if (error)
					*error = "Could not find given group to drop privileges";
				return false;
			}
		}
	}

	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
		CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW, -1);
	if (capng_change_id(uid, gid, CAPNG_DROP_SUPP_GRP | CAPNG_CLEAR_BOUNDING))
	{
		if (error)
			*error = "Could not drop privileges";
		return false;
	}
	return true;
#else
	errno = 0;
	*error = "Can only drop privileges on Linux";
	return false;
#endif
}

static bool obtain_server_id(const char *if_, struct sockaddr_in *out, const char **error)
{
	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) == -1)
	{
		if (error)
			*error = "Could not get interface information";
		return false;
	}

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET && !strcmp(ifa->ifa_name, if_))
		{
			*out = *(struct sockaddr_in *)(ifa->ifa_addr);
			break;
		}
	}

	freeifaddrs(ifaddrs);

	return true;
}

int main(int argc, char **argv)
{
	int err;
	const char *errstr;

	const char *db = "eth0.db";
	const char *interface = "eth0";

	/* Set client IP address */
	broadcast.sin_port = htons(68);

	config = json_object();

	for (int off = 1; off < argc; ++off)
	{
		json_t *new_config;
		json_error_t json_err;

		char *arg = argv[off];
		if (!strcmp(arg, "-"))
			new_config = json_loadf(stdin, 0, &json_err);
		else if (arg[0] == ':')
			new_config = json_loads(arg + 1, 0, &json_err);
		else
			new_config = json_load_file(arg, 0, &json_err);

		if (!new_config)
			dhcpd_error(1, 0, "Config error: %s at %s:%u:%u", json_err.text,
				json_err.source, json_err.line, json_err.column);

		if (!json_is_object(new_config))
			dhcpd_error(1, 0, "Expected configuration '%s' to contain JSON object", arg);

		json_object_update(config, new_config);
		json_decref(new_config);
	}

	if (json_is_string(json_object_get(config, "user")))
	{
		json_t *cf_user = json_object_get(config, "user");
		json_t *cf_group = json_object_get(config, "group");
		err = drop_privileges(json_string_value(cf_user),
			json_is_string(cf_group) ? json_string_value(cf_group) : NULL,
			&errstr);
		if (!err)
			dhcpd_error(1, errno, errstr);
	}

	{
		json_t *cf_database = json_object_get(config, "database");
		json_t *cf_interface = json_object_get(config, "interface");
		json_t *cf_debug = json_object_get(config, "debug");

		if (json_is_string(cf_database))
			db = json_string_value(cf_database);
		if (json_is_string(cf_interface))
			interface = json_string_value(cf_interface);
		if (json_is_boolean(cf_debug))
			debug = json_is_true(cf_debug);
	}

	err = mdb_env_create(&menv);
	if (err != 0)
		dhcpd_error(1, 0, "MDB error: mdb_env_create: %s", mdb_strerror(err));

	err = mdb_env_open(menv, db, MDB_NOSUBDIR, 0600);
	if (err != 0)
		dhcpd_error(1, 0, "MDB error: mdb_env_open: %s", mdb_strerror(err));

	int sock;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		dhcpd_error(1, errno, "Could not create socket");

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(67),
		.sin_addr = {INADDR_ANY}
	};

	err = obtain_server_id(interface, &server_id, &errstr);
	if (!err)
		dhcpd_error(1, errno, errstr);

	err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
	if (err)
		dhcpd_error(1, errno, "Could not set SO_REUSEADDR");

	/* Bind to DHCP address */
	err = bind(sock, (const struct sockaddr *)&bind_addr, sizeof bind_addr);
	if (err)
		dhcpd_error(1, errno, "Could not bind to 0.0.0.0:67");

	/* Set broadcast socket option for Broadcast operations */
	err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int));
	if (err)
		dhcpd_error(1, errno, "Could not set SO_BROADCAST");

#ifdef __linux__
	/* Bind to device on Linux systems */
	err = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));
	if (err)
		dhcpd_error(1, errno, "Could not SO_BINDTODEVICE to %s", interface);

#if 0
	err = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (int[]){1}, sizeof(int));
	if (err)
		dhcpd_error(1, errno, "Could not set SO_REUSEPORT");
#endif
#endif

	struct ev_loop *loop = EV_DEFAULT;

	ev_io read_watch;
	ev_signal sigint_watch, sigusr1_watch, sigusr2_watch, sigterm_watch;

	/* Register IO watcher for UDP socket */
	ev_io_init(&read_watch, req_cb, sock, EV_READ);
	ev_io_start(loop, &read_watch);

	/* Register Signal watcher for SIGINT */
	ev_signal_init(&sigint_watch, sigint_cb, SIGINT);
	ev_signal_start(loop, &sigint_watch);

	/* Register Signal watcher for SIGTERM */
	ev_signal_init(&sigterm_watch, sigint_cb, SIGTERM);
	ev_signal_start(loop, &sigterm_watch);

	/* Register Signal watcher for SIGUSR1 */
	ev_signal_init(&sigusr1_watch, sigusr1_cb, SIGUSR1);
	ev_signal_start(loop, &sigusr1_watch);

	/* Register Signal watcher for SIGUSR2 */
	ev_signal_init(&sigusr2_watch, sigusr2_cb, SIGUSR2);
	ev_signal_start(loop, &sigusr2_watch);

	/* Run event loop */
	ev_run(loop, 0);

	/* Free ev default loop to make valgrind happy */
	ev_loop_destroy(loop);
	json_decref(config);

	mdb_env_close(menv);
}

