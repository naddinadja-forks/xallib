#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <xal_pool.h>

#include "test.h"

#define ELEMENT_SIZE 64
#define RESERVED     1024
#define GROWBY       16

static int
test_map_basic(void)
{
	struct xal_pool pool = {0};
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(pool.reserved == RESERVED);
	TEST_ASSERT(pool.element_size == ELEMENT_SIZE);
	TEST_ASSERT(pool.growby == GROWBY);
	TEST_ASSERT(pool.free == 0);
	TEST_ASSERT(pool.memory != NULL);

	xal_pool_unmap(&pool);
	return 0;
}

static int
test_map_already_initialized(void)
{
	struct xal_pool pool = {0};
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == -EINVAL);

	xal_pool_unmap(&pool);
	return 0;
}

static int
test_map_allocated_exceeds_reserved(void)
{
	struct xal_pool pool = {0};
	int err;

	err = xal_pool_map(&pool, RESERVED, RESERVED + 1, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == -EINVAL);

	return 0;
}

static int
test_claim_sequential_indices(void)
{
	struct xal_pool pool = {0};
	uint32_t idx;
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);

	err = xal_pool_claim_inodes(&pool, 1, &idx);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(idx == 0);

	err = xal_pool_claim_inodes(&pool, 1, &idx);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(idx == 1);

	err = xal_pool_claim_inodes(&pool, 3, &idx);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(idx == 2);
	TEST_ASSERT(pool.free == 5);

	xal_pool_unmap(&pool);
	return 0;
}

static int
test_claim_triggers_growth(void)
{
	struct xal_pool pool = {0};
	uint32_t idx;
	size_t i;
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(pool.allocated == GROWBY);

	for (i = 0; i < GROWBY; i++) {
		err = xal_pool_claim_inodes(&pool, 1, &idx);
		TEST_ASSERT(err == 0);
	}

	TEST_ASSERT(pool.free == GROWBY);

	err = xal_pool_claim_inodes(&pool, 1, &idx);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(pool.allocated == GROWBY * 2);
	TEST_ASSERT(pool.free == GROWBY + 1);

	xal_pool_unmap(&pool);
	return 0;
}

static int
test_claim_count_exceeds_growby(void)
{
	struct xal_pool pool = {0};
	uint32_t idx;
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);

	err = xal_pool_claim_inodes(&pool, GROWBY + 1, &idx);
	TEST_ASSERT(err == -EINVAL);

	xal_pool_unmap(&pool);
	return 0;
}

static int
test_clear_resets_pool(void)
{
	struct xal_pool pool = {0};
	uint8_t *mem;
	uint32_t idx;
	size_t i;
	int err;

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, NULL);
	TEST_ASSERT(err == 0);

	for (i = 0; i < 4; i++) {
		err = xal_pool_claim_inodes(&pool, 1, &idx);
		TEST_ASSERT(err == 0);
	}

	TEST_ASSERT(pool.free == 4);

	err = xal_pool_clear(&pool);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(pool.free == 0);
	TEST_ASSERT(pool.allocated == 0);

	mem = pool.memory;
	for (i = 0; i < RESERVED * ELEMENT_SIZE; i++) {
		TEST_ASSERT(mem[i] == 0);
	}

	xal_pool_unmap(&pool);
	return 0;
}

int
main(void)
{
	int failures = 0;

	TEST_RUN(test_map_basic);
	TEST_RUN(test_map_already_initialized);
	TEST_RUN(test_map_allocated_exceeds_reserved);
	TEST_RUN(test_claim_sequential_indices);
	TEST_RUN(test_claim_triggers_growth);
	TEST_RUN(test_claim_count_exceeds_growby);
	TEST_RUN(test_clear_resets_pool);

	return failures;
}
