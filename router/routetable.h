#ifndef ROUTE_TABLE_H
#define ROUTE_TABLE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_lpm.h>
#include <rte_hash.h>

uint32_t port2ip[4][2];

struct route_table {
    struct rte_lpm *lpm;
    struct rte_hash *nexthop2key;
    uint32_t item[0];
};

struct route_table* 
create_route_table(uint32_t size);

int 
add_staticroute(struct route_table *route_table);
        
#endif
