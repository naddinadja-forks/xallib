#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <xal_pool.h>

#include "test.h"

#define ELEMENT_SIZE 64
#define RESERVED     256
#define GROWBY       16

/*
 * Unlike the anonymous path, the shm path commits the full reserved size upfront.
 * allocated and growby are both set to reserved, not to the growby argument.
 */
static int
test_shm_map_basic(void)
{
	struct xal_pool pool = {0};
	const char *name = "/xal_test_shm_basic";
	int err;

	shm_unlink(name); // cleanup for any failed previous tests

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, name);
	TEST_ASSERT(err == 0);
	TEST_ASSERT(pool.reserved == RESERVED);
	TEST_ASSERT(pool.element_size == ELEMENT_SIZE);
	TEST_ASSERT(pool.allocated == RESERVED);
	TEST_ASSERT(pool.growby == RESERVED);
	TEST_ASSERT(pool.free == 0);
	TEST_ASSERT(pool.memory != NULL);

	xal_pool_unmap(&pool);
	shm_unlink(name);
	return 0;
}

static int
test_shm_map_memory_accessible(void)
{
	struct xal_pool pool = {0};
	const char *name = "/xal_test_shm_accessible";
	uint8_t *mem;
	int err;

	shm_unlink(name); // cleanup for any failed previous tests

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, name);
	TEST_ASSERT(err == 0);

	mem = pool.memory;
	mem[0] = 0xFF;
	TEST_ASSERT(mem[0] == 0xFF);

	xal_pool_unmap(&pool);
	shm_unlink(name);
	return 0;
}

static int
test_shm_claim_sequential_indices(void)
{
	struct xal_pool pool = {0};
	const char *name = "/xal_test_shm_claim";
	uint32_t idx;
	int err;

	shm_unlink(name); // cleanup for any failed previous tests

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, name);
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
	shm_unlink(name);
	return 0;
}

/*
 * Verify that a second mapping of the same shm object sees data written through
 * the first. This simulates the cross-process sharing that xal_from_pools() relies on.
 */
static int
test_shm_two_mappings_share_memory(void)
{
	struct xal_pool pool = {0};
	const char *name = "/xal_test_shm_share";
	size_t nbytes = RESERVED * ELEMENT_SIZE;
	uint8_t *mem_a, *mem_b;
	int fd, err;

	shm_unlink(name); // cleanup for any failed previous tests

	err = xal_pool_map(&pool, RESERVED, GROWBY, ELEMENT_SIZE, name);
	TEST_ASSERT(err == 0);

	mem_a = pool.memory;
	mem_a[0] = 0xAB;

	fd = shm_open(name, O_RDONLY, 0);
	TEST_ASSERT(fd >= 0);

	mem_b = mmap(NULL, nbytes, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	TEST_ASSERT(mem_b != MAP_FAILED);

	TEST_ASSERT(mem_b[0] == 0xAB);

	munmap(mem_b, nbytes);
	xal_pool_unmap(&pool);
	shm_unlink(name);
	return 0;
}

int
main(void)
{
	int failures = 0;

	TEST_RUN(test_shm_map_basic);
	TEST_RUN(test_shm_map_memory_accessible);
	TEST_RUN(test_shm_claim_sequential_indices);
	TEST_RUN(test_shm_two_mappings_share_memory);

	return failures;
}
