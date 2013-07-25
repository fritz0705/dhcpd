#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>

struct pool_entry {
  time_t acquired_at;
  bool own;
  struct in_addr address;
};


struct pool {
  uint32_t limit; // current array size
  uint32_t size; // index of last entry
  struct pool_entry *a;
};

struct pool *pool_create();
void pool_destroy(struct pool *pool);

// May return NULL if empty
struct pool_entry *pool_get(struct pool *pool);

void pool_add(struct pool *pool, struct pool_entry *entry);

void pool_resize(struct pool *pool, uint32_t limit);
