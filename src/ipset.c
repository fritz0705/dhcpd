#include "ipset.h"

#include <stdlib.h>

#include "tree.h"

struct ipset {
	uint32_t prefix;
	uint8_t prefixlen;
	uint8_t *bitmap;
};

ipset_t ipset_create(uint32_t prefix, uint8_t prefixlen)
{
	ipset_t self = malloc(sizeof *self);
	self->prefix = prefix;
	self->prefixlen = prefixlen;
	return self;
}

bool ipset_add(ipset_t self, uint32_t address)
{
	(void)self;
	(void)address;
	return false;
}

bool ipset_remove(ipset_t self, uint32_t address)
{
	(void)self;
	(void)address;
	return false;
}

bool ipset_contains(ipset_t self, uint32_t address)
{
	(void)self;
	(void)address;
	return false;
}

bool ipset_pop(ipset_t self, uint32_t *address)
{
	(void)self;
	(void)address;
	return false;
}

bool ipset_allocate(ipset_t self, uint32_t *address)
{
	(void)self;
	(void)address;
	return false;
}

size_t ipset_size(ipset_t self)
{
	(void)self;
	return 0;
}

size_t ipset_capacity(ipset_t self)
{
	return 1 << (32 - self->prefixlen);
}

void ipset_destroy(ipset_t self)
{
	free(self);
}
