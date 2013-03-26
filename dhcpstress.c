#include "error.h"
#include "dhcp.h"

#include <net/if.h>
#include <errno.h>

#include <arpa/inet.h>

#define SEND_BUF_LEN 4096

uint8_t send_buffer[SEND_BUF_LEN];

int main(int argc, char **argv)
{
	if (argc < 2)
		dhcpd_error(1, 0, "Usage: dhcpstress INTERFACE [IP]");

	char *interface = argv[1];

	if (if_nametoindex(interface) == 0)
		dhcpd_error(1, errno, interface);

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(68),
		.sin_addr = {INADDR_ANY}
	};
	
	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(67),
		.sin_addr = {INADDR_BROADCAST}
	};

	if (argc >= 3)
		inet_pton(AF_INET, argv[2], &server_addr.sin_addr);

	int sock;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		dhcpd_error(1, errno, "Could not create client socket");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set socket to reuse address");
	if (bind(sock, (const struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) < 0)
		dhcpd_error(1, errno, "Could not bind to 0.0.0.0:67");
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int)) != 0)
		dhcpd_error(1, errno, "Could not set broadcast socket option");
#ifdef __linux__
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) != 0)
		dhcpd_error(1, errno, "Could not bind to device %s", interface);
#endif

	size_t send_len;
	send_len = DHCP_MSG_HDRLEN;
	memset(send_buffer, 0, DHCP_MSG_LEN);

	*DHCP_MSG_F_OP(send_buffer) = 1;
	*DHCP_MSG_F_HTYPE(send_buffer) = 1;
	*DHCP_MSG_F_HLEN(send_buffer) = 6;
	ARRAY_COPY(DHCP_MSG_F_MAGIC(send_buffer), DHCP_MSG_MAGIC, 4);

	uint8_t *options = DHCP_MSG_F_OPTIONS(send_buffer);
	options[0] = DHCP_OPT_MSGTYPE;
	options[1] = 1;
	options[2] = DHCPDISCOVER;
	DHCP_OPT_CONT(options, send_len);

	options[0] = DHCP_OPT_ROUTER;
	options[1] = 255;
	options += 2;
	send_len += 2;

	options[0] = DHCP_OPT_END;
	DHCP_OPT_CONT(options, send_len);

	while (1)
		sendto(sock, send_buffer, send_len, MSG_DONTWAIT,
			(struct sockaddr *)&server_addr, sizeof server_addr);
}

