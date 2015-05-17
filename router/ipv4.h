#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

struct lcore_env;

int
ip_in(struct rte_mbuf *buf);

int
is_my_ip(uint32_t addr);

int
swap_ipaddr(struct rte_mbuf *buf);
#endif
