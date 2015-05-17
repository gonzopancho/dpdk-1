#ifndef ROUTEMARIO_RUNTIME_H
#define ROUTEMARIO_RUNTIME_H

#include <rte_mbuf.h>

#define MAX_PKT_BURST 32

struct fdb_table;
struct arp_table;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_env {
  uint8_t n_port;
  uint8_t lcore_id;
  struct fdb_table* fdb;
  struct arp_table* arp_tb;
  struct mbuf_table tx_mbufs[0];
};


static int is_own_ip_addr(uint32_t addr) {
    return 1;
}
#endif
