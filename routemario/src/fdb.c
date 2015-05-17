/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_hash.h>

#include "fdb.h"
#include "util.h"

#define mmalloc(x) rte_malloc("fdb", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_FDB RTE_LOGTYPE_USER1

struct fdb_table*
create_fdb_table(uint32_t _size)
{
  rte_srand((unsigned) time (NULL));
  uint32_t seed = (uint32_t) rte_rand();
  uint32_t size = (uint32_t) POWERROUND(_size);
  size = size > RTE_HASH_ENTRIES_MAX? RTE_HASH_ENTRIES_MAX : size;

  struct fdb_table *table;
  table = (struct fdb_table*) mmalloc(sizeof(struct fdb_table) +
                                      sizeof(struct fdb_entry) * size);
  if (table == NULL) {
    RTE_LOG( ERR, FDB, "cannot allocate memory for table.\n");
    goto out;
  }
  
  struct rte_hash_parameters params = {
    .name = "fdb",
    .entries = size,
    .bucket_entries = RTE_HASH_BUCKET_ENTRIES_MAX,
    .key_len = 6,
    .hash_func = rte_jhash,
    .hash_func_init_val = seed,
    .socket_id = (int) rte_socket_id()
  };
  table->handler = rte_hash_create(&params);
  if (table->handler == NULL) {
    RTE_LOG(ERR, FDB,
            "cannot create rte_hash: %s.\n", rte_strerror(rte_errno));
    goto free;
  }

  return table;
free:
  mfree(table->handler);
out:
  return NULL;  
}

void
destroy_fdb_table(struct fdb_table* table)
{
  rte_hash_free(table->handler);
  mfree(table->items);
}

int
add_fdb_entry(struct fdb_table* table, const struct ether_addr* addr,
              const uint16_t port)
{
  int32_t key = rte_hash_add_key(table->handler, addr);
  if (key >= 0) {
    struct fdb_entry *entry = &table->items[key];
    ether_addr_copy(addr, &entry->addr);
    entry->port = port;
    entry->aging = AGING_TIME;
    return 0;
  }

  if (key == -ENOSPC) {
    RTE_LOG(WARNING, FDB, "no space in the hash for this key.\n");
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, FDB, "Invalid parameters.\n");
      break;
    case ENOSPC:
      RTE_LOG(WARNING, FDB, "no space in the hash for this key.\n");
      /* break through */
  }
  return key;
}

int
remove_fdb_entry(struct fdb_table* table, const struct ether_addr* addr)
{
  int32_t key = rte_hash_del_key(table->handler, addr);
  if (key >= 0) {
    struct fdb_entry *entry = &table->items[key];
    ether_addr_copy((struct ether_addr*) "000000", &entry->addr);
    entry->port = 0;
    entry->aging = 0;
    
    return 0;
  }

  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, FDB, "Invalid parameters.\n");
      break;
    case ENOENT:
      RTE_LOG(WARNING, FDB, "the key is not found.\n");
      /* break through */
  }
  return key;
}

struct fdb_entry*
lookup_fdb_entry(struct fdb_table* table, const struct ether_addr* addr)
{
  int32_t key = rte_hash_lookup(table->handler, (void*) addr);
  if (key >= 0) {
    struct fdb_entry *entry = &table->items[key];
    return entry;
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, FDB, "Invalid parameters.\n");
      break;
    case ENOENT:
      ;
      //RTE_LOG(WARNING, FDB, "the key is not found.\n");
      /* break through */
  }
  return NULL;
}

int
lookup_bulk_fdb_entries(struct fdb_table* table,
                        const struct ether_addr** addrs,
                        uint32_t num_entry, struct fdb_entry** entries)
{
  int32_t positions[num_entry];
  int res = rte_hash_lookup_bulk(table->handler, (const void**) addrs,
                                 num_entry, (int32_t*) positions);
  if (res ==  0) {
    for (uint32_t i = 0; i < num_entry; i++) {
      // XXX: inline extraction 
      entries[i] = &table->items[positions[i]];
    }
    return 0;
  }
  
  RTE_LOG(ERR, FDB, "error.\n");
  return res;
}
