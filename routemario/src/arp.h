#ifndef ARP_H
#define ARP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#define ARP_TABLE_EXPIRE_TIME 300

struct lcore_env;

struct arp_table_entry {
  struct ether_addr eth_addr;
  uint32_t ip_addr;
  uint32_t expire;
};

struct arp_table {
  struct rte_hash *handler;
  struct arp_table_entry items[0];
};

struct arp_table*
create_arp_table(uint32_t size);

void
destroy_arp_table(struct arp_table* table);

int
add_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr,
                    const struct ether_addr* addr);

int
remove_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr);

struct arp_table_entry*
lookup_arp_entry(struct arp_table* table, const uint32_t *ip_addr);

int
lookup_bulk_arp_table_entries(struct arp_table *talbe, 
                              const uint32_t **ip_addrs,
                              uint32_t num_entry,
                              struct arp_table_entry** entries);

int
arp_input(struct lcore_env* env, struct rte_mbuf* buf);

#endif
