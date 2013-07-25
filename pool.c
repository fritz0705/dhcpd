#include <stdlib.h>
#include <string.h>

#include "pool.h"

struct pool *pool_create() {
	struct pool *pool;

	pool = (struct pool*)malloc(sizeof(struct pool));

	pool->limit = 0;
	pool->size = 0;
	pool->a = NULL;

	return pool;
}

void pool_destroy(struct pool *pool) {
	free(pool->a);
	free(pool);
}

struct pool_entry *pool_get(struct pool *pool) {
	struct pool_entry *entry;

	if (pool->size == 0)
		return NULL;

	entry = (struct pool_entry*)malloc(sizeof(struct pool_entry));
	memcpy(entry, &pool->a[--pool->size], sizeof(struct pool_entry));

	return entry;
}

void pool_add(struct pool *pool, struct pool_entry *entry) {
	if (pool->limit < pool->size + 1)
		pool_resize(pool, pool->limit + 1);

	memcpy(&pool->a[pool->size++], entry, sizeof(struct pool_entry));
}

void pool_resize(struct pool *pool, uint32_t limit) {
  pool->a = (struct pool_entry*)realloc(pool->a,
			sizeof(struct pool_entry) * limit);

	pool->limit = limit;

	if (pool->size > pool->limit)
		pool->size = pool->limit;
}
