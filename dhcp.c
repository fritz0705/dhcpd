#include "dhcp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static uint32_t netmask_from_prefixlen(uint8_t prefixlen)
{
	return htonl(0xFFFFFFFFU - (1 << (32 - prefixlen)) + 1);
}

uint8_t *dhcp_opt_add_lease(uint8_t *options, size_t *_send_len, struct dhcp_lease *lease)
{
	size_t send_len = 0;

	if (lease->prefixlen > 0)
	{
		options[0] = DHCP_OPT_NETMASK;
		options[1] = 1;
		ARRAY_COPY((options + 2), (uint8_t*)((uint32_t[]){netmask_from_prefixlen(lease->prefixlen)}), 4);
		DHCP_OPT_CONT(options, send_len);
	}

	if (lease->routers_cnt > 0)
	{
		options[0] = DHCP_OPT_ROUTER;
		options[1] = lease->routers_cnt * 4;
		for (off_t i = 0; i < lease->routers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease->routers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	if (lease->leasetime > 0)
	{
		options[0] = DHCP_OPT_LEASETIME;
		options[1] = 4;
		*(uint32_t*)(options + 2) = htonl(lease->leasetime);
		DHCP_OPT_CONT(options, send_len);
	}

	if (lease->nameservers_cnt > 0)
	{
		options[0] = DHCP_OPT_DNS;
		options[1] = lease->nameservers_cnt * 4;
		for (size_t i = 0; i < lease->nameservers_cnt; ++i)
			*(struct in_addr *)(options + 2 + (i * 4)) = lease->nameservers[i];
		DHCP_OPT_CONT(options, send_len);
	}

	if (_send_len != NULL)
		*_send_len += send_len;

	return options;
}

void dhcp_msg_dump(FILE *stream, struct dhcp_msg *msg)
{
	fprintf(stream,
		"DHCP message:\n"
		"\tOP %hhu [%s]\n"
		"\tHTYPE %hhu HLEN %hhu\n"
		"\tHOPS %hhu\n"
		"\tXID %8X\n"
		"\tSECS %hu FLAGS %hu\n"
		"\tCIADDR %s YIADDR %s SIADDR %s GIADDR %s\n"
		"\tCHADDR %s\n"
		"\tMAGIC %8X\n"
		"\tMSG TYPE %s\n",
		*DHCP_MSG_F_OP(msg->data),
		(*DHCP_MSG_F_OP(msg->data) == 1 ? "REQUEST" : "REPLY"),
		*DHCP_MSG_F_HTYPE(msg->data),
		*DHCP_MSG_F_HLEN(msg->data),
		*DHCP_MSG_F_HOPS(msg->data),
		ntohl(*DHCP_MSG_F_XID(msg->data)),
		ntohs(*DHCP_MSG_F_SECS(msg->data)),
		ntohs(*DHCP_MSG_F_FLAGS(msg->data)),
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
			case DHCP_OPT_REQIPADDR:
				fprintf(stream, "\tOPTION REQIPADDR %s\n",
					inet_ntop(AF_INET, cur_opt.data,
						(char[]){[INET_ADDRSTRLEN] = 0}, INET_ADDRSTRLEN));
				break;
			default:
				fprintf(stream, "\tOPTION %02hhX(%hhu)\n", cur_opt.code, cur_opt.len);
				break;
		}
	}
}

