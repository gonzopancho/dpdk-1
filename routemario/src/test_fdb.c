/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_ether.h>

#include "fdb.h"

#define TEST_NUM 1 << 18
#define TABLE_SIZE 1 << 20
#define RTE_LOGTYPE_FDB_TEST RTE_LOGTYPE_USER1

int
main(int argc, char **argv)
{
  int ret;
  ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

  RTE_LOG(INFO, FDB_TEST, "creating fdb_table.\n");
  struct fdb_table *table = create_fdb_table(TABLE_SIZE);
  if (table == NULL) {
    rte_exit(EXIT_FAILURE, "fail to create fdb table.");
  }

  RTE_LOG(INFO, FDB_TEST, "adding %u entries...\n", TEST_NUM);
  for(uint32_t i = 0; i < TEST_NUM; i++) {
    struct ether_addr addr;
    for (int j = 0; j < ETHER_ADDR_LEN; j++) {
      addr.addr_bytes[j] = (uint8_t)(i >> (8 * j));
    }
    int res = add_fdb_entry(table, &addr, (i & 0xffff));
    if (res < 0) {
      RTE_LOG(ERR, FDB_TEST, "Could not add entry: %u\n", i);
      assert(false);
    }
  }
  RTE_LOG(INFO, FDB_TEST, "done\n");

  RTE_LOG(INFO, FDB_TEST, "lookuping %u entries...\n", TEST_NUM);
  for(uint32_t i = 0; i < TEST_NUM; i++) {
    struct ether_addr addr;
    for (int j = 0; j < ETHER_ADDR_LEN; j++) {
      addr.addr_bytes[j] = (uint8_t)(i >> (8 * j));
    }

    struct fdb_entry *entry = lookup_fdb_entry(table, &addr);
    if (entry == NULL) {
      RTE_LOG(ERR, FDB_TEST, "Not found entry: %u\n", i);
      assert(false);
    }
    assert(entry->port == (i & 0xffff));
  }
  RTE_LOG(INFO, FDB_TEST, "done\n");

  RTE_LOG(INFO, FDB_TEST, "deleting %u entries...\n", TEST_NUM);
  for(uint32_t i = 0; i < TEST_NUM; i++) {
    struct ether_addr addr;
    for (int j = 0; j < ETHER_ADDR_LEN; j++) {
      addr.addr_bytes[j] = (uint8_t)(i >> (8 * j));
    }

    int res = remove_fdb_entry(table, &addr);
    if (res > 0) {
      RTE_LOG(ERR, FDB_TEST, "remove error: %u\n", i);
      assert(false);
    }
  }
  RTE_LOG(INFO, FDB_TEST, "done\n");
  
  RTE_LOG(INFO, FDB_TEST, "relookuping %u entries...\n", TEST_NUM);
  for(uint32_t i = 0; i < TEST_NUM; i++) {
    struct ether_addr addr;
    for (int j = 0; j < ETHER_ADDR_LEN; j++) {
      addr.addr_bytes[j] = (uint8_t)(i >> (8 * j));
    }

    struct fdb_entry *entry = lookup_fdb_entry(table, &addr);
    if (entry != NULL) {
      RTE_LOG(ERR, FDB_TEST, "%u-th entry found...\n", i);
      assert(false);
    }
  }
  RTE_LOG(INFO, FDB_TEST, "Nothing found!!\n");
  

  return 0;
}
