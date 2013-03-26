#include "dhcp.h"

#include <sys/types.h>
#include <arpa/inet.h>

void dhcp_msg_dump(FILE *stream, struct dhcp_msg *msg)
{
	fprintf(stream,
		"DHCP message from %s:\n"
		"\tOP %hhu [%s]\n"
		"\tHTYPE %hhu HLEN %hhu\n"
		"\tHOPS %hhu\n"
		"\tXID %8X\n"
		"\tSECS %hu FLAGS %hu\n"
		"\tCIADDR %s YIADDR %s SIADDR %s GIADDR %s\n"
		"\tCHADDR %s\n"
		"\tMAGIC %8X\n"
		"\tMSG TYPE %s\n",
		msg->srcaddr,
		*DHCP_MSG_F_OP(msg->data),
		(*DHCP_MSG_F_OP(msg->data) == 1 ? "REQUEST" : "REPLY"),
		*DHCP_MSG_F_HTYPE(msg->data),
		*DHCP_MSG_F_HLEN(msg->data),
		*DHCP_MSG_F_HOPS(msg->data),
		ntohl(*DHCP_MSG_F_XID(msg->data)),
		ntohl(*DHCP_MSG_F_SECS(msg->data)),
		ntohl(*DHCP_MSG_F_FLAGS(msg->data)),
		msg->ciaddr, msg->yiaddr, msg->siaddr, msg->giaddr,
		msg->chaddr,
		*(uint32_t*)DHCP_MSG_F_MAGIC(msg->data),
		(msg->type == DHCPDISCOVER ? "DHCPDISCOVER" :
		 msg->type == DHCPOFFER ? "DHCPOFFER" :
		 msg->type == DHCPREQUEST ? "DHCPREQUEST" :
		 msg->type == DHCPDECLINE ? "DHCPDECLINE" :
		 msg->type == DHCPACK ? "DHCPACK" :
		 msg->type == DHCPNAK ? "DHCPNAK" :
		 msg->type == DHCPRELEASE ? "DHCPRELEASE" :
		 msg->type == DHCPINFORM ? "DHCPINFORM" : "unknown"));

	struct dhcp_opt cur_opt;
	uint8_t *options = DHCP_MSG_F_OPTIONS(msg->data);

	while (dhcp_opt_next(&options, &cur_opt, msg->end))
	{
		switch (cur_opt.code)
		{
			case DHCP_OPT_STUB:
				fprintf(stream, "\tOPTION STUB\n");
				break;
			case DHCP_OPT_NETMASK:
				fprintf(stream, "\tOPTION NETMASK %s\n",
					inet_ntop(AF_INET, cur_opt.data,
						(char[]){[INET_ADDRSTRLEN] = 0}, INET_ADDRSTRLEN));
				break;
			case DHCP_OPT_ROUTER:
				fprintf(stream, "\tOPTION ROUTERS %u\n", cur_opt.len / 4);
				for (off_t o = 0; o < cur_opt.len / 4; ++o)
					fprintf(stream, "\t\t%s\n", inet_ntop(AF_INET, cur_opt.data+(o*4),
							(char[]){[INET_ADDRSTRLEN] = 0}, INET_ADDRSTRLEN));
				break;
			case DHCP_OPT_DNS:
				fprintf(stream, "\tOPTION DNS %u\n", cur_opt.len / 4);
				for (off_t o = 0; o < cur_opt.len / 4; ++o)
					fprintf(stream, "\t\t%s\n", inet_ntop(AF_INET, cur_opt.data+(o*4),
							(char[]){[INET_ADDRSTRLEN] = 0}, INET_ADDRSTRLEN));
				break;
			case DHCP_OPT_LEASETIME:
				fprintf(stream, "\tOPTION LEASETIME %u\n", *(uint32_t*)cur_opt.data);
				break;
			case DHCP_OPT_SERVERID:
				fprintf(stream, "\tOPTION SERVERID %s\n",
					inet_ntop(AF_INET, cur_opt.data,
						(char[]){[INET_ADDRSTRLEN] = 0}, INET_ADDRSTRLEN));
				break;
			default:
				fprintf(stream, "\tOPTION %02hhX(%hhu)\n", cur_opt.code, cur_opt.len);
				break;
		}
	}
}

