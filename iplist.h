#pragma once
/* Tools to work with lists of IP addresses */

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static inline bool iplist_dump(struct in_addr *in, size_t in_cnt, char *out, size_t out_len)
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

	return true;
}

static inline bool iplist_parse(const char *in, struct in_addr **out, size_t *cnt)
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

