#ifndef FDB_H
#define FDB_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <rte_ether.h>
#include <rte_hash.h>


#define AGING_TIME 3600


struct fdb_entry {
  struct ether_addr addr;
  uint16_t port;
  /**
   * XXX:
   * updating aging cause cache invalidation in other core.
   * so we had not better updating it !?
   * should be better to use rte_timer !?
   */
  uint32_t aging; 
};

struct fdb_table {
  struct rte_hash *handler;
  struct fdb_entry items[0];
};

struct fdb_table*
create_fdb_table(uint32_t size);

void
destroy_fdb_table(struct fdb_table* table);

int
add_fdb_entry(struct fdb_table* table, const struct ether_addr* addr,
              const uint16_t port);

int
remove_fdb_entry(struct fdb_table* table, const struct ether_addr* addr);

struct fdb_entry*
lookup_fdb_entry(struct fdb_table* table, const struct ether_addr* addr);

int
lookup_bulk_fdb_entries(struct fdb_table* talbe, 
                        const struct ether_addr** addrs,
                        uint32_t num_entry, struct fdb_entry** entries);
#endif
