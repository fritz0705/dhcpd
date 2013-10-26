#include "dhcp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void dhcp_msg_dumpf(struct dhcp_msg *msg, FILE *stream)
{
	fprintf(stream, "DHCP Message %p Length %zX Type %s\n", msg->data, msg->length,
		(*DHCP_MSG_F_HTYPE(msg->data) == 1) ? "BOOTREQUEST" :
		(*DHCP_MSG_F_HTYPE(msg->data) == 2) ? "BOOTREPLY" : "unknown");
	fprintf(stream, "\tMessage type %s\n", ((const char*[]){
			[DHCPDISCOVER] = "DHCPDISCOVER",
			[DHCPOFFER] = "DHCPOFFER",
			[DHCPREQUEST] = "DHCPREQUEST",
			[DHCPDECLINE] = "DHCPDECLINE",
			[DHCPACK] = "DHCPACK",
			[DHCPNAK] = "DHCPNAK",
			[DHCPRELEASE] = "DHCPRELEASE",
			[DHCPINFORM] = "DHCPINFORM"
		})[msg->type]);
	fprintf(stream, "\tOptions\n");

	uint8_t *options = DHCP_MSG_F_OPTIONS(msg->data);
	struct dhcp_opt current_option;

	while (dhcp_opt_next(&options, &current_option, msg->data + msg->length))
	{
		switch (current_option.code)
		{
			case DHCP_OPT_STUB:
				break;

			case DHCP_OPT_NETMASK:
				break;

			case DHCP_OPT_ROUTER:
				break;

			case DHCP_OPT_DNS:
				break;

			case DHCP_OPT_REQIPADDR:
				break;

			case DHCP_OPT_LEASETIME:
				break;

			case DHCP_OPT_MSGTYPE:
				break;

			case DHCP_OPT_SERVERID:
				break;
				
			case DHCP_OPT_END:
				break;
		}
	}
}

