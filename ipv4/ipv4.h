#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

struct lcore_env;

int
ip_input(struct lcore_env *env, struct rte_mbuf *buf);

int
ip_output(struct lcore_env *env, struct rte_mbuf *buf);

#endif
