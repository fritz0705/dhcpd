#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>

#ifndef DHCPD_IPSET_H_
#define DHCPD_IPSET_H_

typedef struct ipset *ipset_t;

typedef struct ipset *ipset_t;

ipset_t ipset_create(uint32_t prefix, uint8_t prefixlen);

bool ipset_add(ipset_t, uint32_t);
bool ipset_remove(ipset_t, uint32_t);

bool ipset_contains(ipset_t, uint32_t);

bool ipset_pop(ipset_t, uint32_t *);
bool ipset_allocate(ipset_t, uint32_t *);

size_t ipset_size(ipset_t);
size_t ipset_capacity(ipset_t);

void ipset_destroy(ipset_t);

#endif
