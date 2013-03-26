#include "error.h"
#include "dhcp.h"

#include <net/if.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>

struct argv
{
	char **argv;
	int argc;
	int argerror;

	char *arg0;

	/* -stress NAME */
	char *stress;
	/* -interface IF */
	char *interface;
	/* -remote IP PORT */
	char *remote[2];
	/* -local IP PORT */
	char *local[2];
	/* -sleep TIME */
	char *sleep;
	/* -seed NUM */
	char *seed;
	/* -type NUM */
	char *type;

	/* -help */
	bool help;
	/* -stresses */
	bool stresses;
};

#define ARGV_EMPTY {\
		.argv = NULL,\
		.argc = 0,\
		.arg0 = NULL,\
		.stress = NULL,\
		.interface = NULL,\
		.remote = {NULL, NULL},\
		.local = {NULL, NULL},\
		.sleep = NULL,\
		.seed = NULL,\
		.type = NULL,\
		.help = false,\
		.stresses = false\
	}

struct config
{
	struct argv *argv;
	const char *error;

	struct sockaddr_in remote;
	struct sockaddr_in local;

	uint32_t sleep;
	uint32_t stress;
	uint32_t seed;

	uint8_t type;
};

#define CONFIG_EMPTY {\
		.argv = NULL,\
		.error = NULL,\
		.remote = {\
			.sin_family = AF_INET,\
			.sin_addr = {INADDR_BROADCAST},\
			.sin_port = 67\
		},\
		.local = {\
			.sin_family = AF_INET,\
			.sin_addr = {INADDR_ANY},\
			.sin_port = 68\
		},\
		.sleep = 0,\
		.stress = 0,\
		.seed = 0,\
		.type = 1\
	}

enum argv_p_state
{
	_ARGV_S_ARGUMENT,

	/* Value for -stress */
	_ARGV_S_STRESS_VAL,
	/* Value for -interface */
	_ARGV_S_INTERFACE_VAL,
	/* Value for -remote */
	_ARGV_S_REMOTE_VAL_1,
	/* Second value for -remote */
	_ARGV_S_REMOTE_VAL_2,
	/* First value for -local */
	_ARGV_S_LOCAL_VAL_1,
	/* Second value for -local */
	_ARGV_S_LOCAL_VAL_2,
	/* Value for -sleep */
	_ARGV_S_SLEEP_VAL,
	/* Value for -seed */
	_ARGV_S_SEED_VAL,
	/* Value for -type */
	_ARGV_S_TYPE_VAL
};

static inline bool argv_parse(int argc, char **argv, struct argv *out)
{
	enum argv_p_state state = _ARGV_S_ARGUMENT;

	out->argv = argv;
	out->argc = argc;
	out->arg0 = argv[0];

	for (int i = 1; i < argc; ++i)
	{
		char *arg = argv[i];
		switch (state)
		{
			case _ARGV_S_ARGUMENT:
				if (!strcmp(arg, "-stress"))
					state = _ARGV_S_STRESS_VAL;
				else if (!strcmp(arg, "-interface"))
					state = _ARGV_S_INTERFACE_VAL;
				else if (!strcmp(arg, "-remote"))
					state = _ARGV_S_REMOTE_VAL_1;
				else if (!strcmp(arg, "-local"))
					state = _ARGV_S_LOCAL_VAL_1;
				else if (!strcmp(arg, "-sleep"))
					state = _ARGV_S_SLEEP_VAL;
				else if (!strcmp(arg, "-seed"))
					state = _ARGV_S_SEED_VAL;
				else if (!strcmp(arg, "-type"))
					state = _ARGV_S_TYPE_VAL;
				else if (!strcmp(arg, "-help"))
					out->help = true;
				else if (!strcmp(arg, "-stresses"))
					out->stresses = true;
				else
				{
					out->argerror = i;
					return false;
				}
				break;

			case _ARGV_S_STRESS_VAL:
				out->stress = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_INTERFACE_VAL:
				out->interface = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_REMOTE_VAL_1:
				out->remote[0] = arg;
				state = _ARGV_S_REMOTE_VAL_2;
				break;

			case _ARGV_S_REMOTE_VAL_2:
				out->remote[1] = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_LOCAL_VAL_1:
				out->local[0] = arg;
				state = _ARGV_S_LOCAL_VAL_2;
				break;

			case _ARGV_S_LOCAL_VAL_2:
				out->local[1] = arg;
				state = _ARGV_S_ARGUMENT;
				break;
				
			case _ARGV_S_SLEEP_VAL:
				out->sleep = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_SEED_VAL:
				out->seed = arg;
				state = _ARGV_S_ARGUMENT;
				break;

			case _ARGV_S_TYPE_VAL:
				out->type = arg;
				state = _ARGV_S_ARGUMENT;
				break;
		}
	}

	return true;
}

static inline bool config_fill(struct config *cfg, struct argv *argv)
{
	cfg->argv = argv;

	if (argv->seed)
		cfg->seed = atoi(argv->seed);
	else
		cfg->seed = time(NULL);

	if (argv->stress)
		cfg->stress = atoi(argv->stress);

	if (argv->remote[0] && argv->remote[1])
	{
		cfg->remote = (struct sockaddr_in){
			.sin_family = AF_INET,
			.sin_port = atoi(argv->remote[1])
		};
		if (inet_pton(AF_INET, argv->remote[0], &cfg->remote.sin_addr.s_addr) != 1)
			goto invalid_remote_address;
	}

	if (argv->local[0] && argv->local[1])
	{
		cfg->local = (struct sockaddr_in){
			.sin_family = AF_INET,
			.sin_port = atoi(argv->local[1])
		};
		if (inet_pton(AF_INET, argv->local[0], &cfg->local.sin_addr.s_addr) != 1)
			goto invalid_local_address;
	}

	if (argv->type)
		cfg->type = atoi(argv->type);
	else
	{
		if (cfg->local.sin_port == 67 && cfg->remote.sin_port == 68)
			cfg->type = 1;
		else if (cfg->local.sin_port == 68 && cfg->remote.sin_port == 67)
			cfg->type = 2;
	}

	return true;

	switch (1)
	{
		default:
			break;

invalid_remote_address:
			cfg->error = "Invalid remote address";
			break;

invalid_local_address:
			cfg->error = "Invalid local address";
			break;
	}

	return false;
}

#define SEND_BUF_LEN 4096

uint8_t send_buffer[SEND_BUF_LEN];

struct config cfg = CONFIG_EMPTY;

/* Stress definitions */
static void stress_inval_lenmsgs(int sock);

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

	if (!config_fill(&cfg, &argv_cfg))
		dhcpd_error(1, 0, cfg.error);

	if (argv_cfg.stresses)
	{
		printf(
			"id  function              description\n"
			"1   inval_lenmsgs         Send messages which are longer than the trans-\n"
			"                          mitted byte coud\n");
		exit(0);
	}

	if (argv_cfg.help || argv_cfg.interface == NULL || argv_cfg.stress == NULL)
	{
		printf("%s [-help] [-stresses] [-sleep TIME] [-seed SEED] [-type INT]\n"
			"\t[-stress NAME] [-interface IF] [-remote IP PORT] [-local IP PORT]\n",
			argv_cfg.arg0);
		exit(0);
	}

	cfg.remote.sin_port = htons(cfg.remote.sin_port);
	cfg.local.sin_port = htons(cfg.local.sin_port);

	if (if_nametoindex(cfg.argv->interface) == 0)
		dhcpd_error(1, errno, cfg.argv->interface);

	int sock;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		dhcpd_error(1, errno, "Could not create socket");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set socket to reuse address");
	if (bind(sock, (const struct sockaddr *)&cfg.remote, sizeof(struct sockaddr_in)) < 0)
		dhcpd_error(1, errno, "Could not bind to 0.0.0.0:67");
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set broadcast socket option");
#ifdef __linux__
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, cfg.argv->interface, strlen(cfg.argv->interface)) != 0)
		dhcpd_error(1, errno, "Could not bind to device %s", cfg.argv->interface);
#endif

	switch (cfg.stress)
	{
		case 1:
			stress_inval_lenmsgs(sock);
	}

	exit(0);
}

static void stress_inval_lenmsgs(int sock)
{
	uint32_t val = cfg.seed;

	/* Prepare message */
	size_t send_len = DHCP_MSG_HDRLEN;
	memset(send_buffer, 0, DHCP_MSG_LEN);
	*DHCP_MSG_F_OP(send_buffer) = cfg.type;
	*DHCP_MSG_F_HLEN(send_buffer) = 6;
	*DHCP_MSG_F_HTYPE(send_buffer) = 1;
	ARRAY_COPY(DHCP_MSG_F_MAGIC(send_buffer), DHCP_MSG_MAGIC, 4);

	uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);

	options[0] = DHCP_OPT_MSGTYPE;
	options[1] = 1;
	options[2] = DHCPDISCOVER;
	options[3] = DHCP_OPT_ROUTER;
	options[4] = 252;
	options[5] = DHCP_OPT_END;

	send_len += 6;

	while (1)
	{
		val = val - (val & 0xf0f0f0f0) + (val ^ 0xff);

		*DHCP_MSG_F_XID(send_buffer) = val;
		ARRAY_COPY(DHCP_MSG_F_CHADDR(send_buffer), &val, sizeof val);

		sendto(sock, send_buffer, send_len, 0,
			&cfg.remote, sizeof cfg.remote);
	}
}

