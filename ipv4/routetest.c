#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_random.h>
#include <rte_lpm.h>

#include "routetable.h"

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192
#define ICMPDATASIZE 64
#define MAX_RULE_SIZE 128

struct rte_mempool *mbuf_pool = NULL;
struct route_table *route_table;

int
main(int argc, char **argv)
{
    int ret;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

    printf("\n\n");

    mbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF, MBUF_SIZE, 
						32, sizeof(struct rte_pktmbuf_pool_private), 
                                                rte_pktmbuf_pool_init, NULL,
						                        rte_pktmbuf_init, NULL,
                                                rte_socket_id(), 0);
    if(mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


    route_table = (struct route_table*) rte_malloc(NULL,sizeof(struct route_table),0);
    route_table->lpm = rte_lpm_create("route_table", rte_socket_id(), MAX_RULE_SIZE, 0);

    if(route_table->lpm == NULL){
        printf("cannot create lpm table\n");
        return 1;
    }

    rte_srand((unsigned) time (NULL));
    uint32_t seed = (uint32_t) rte_rand();

    struct rte_hash_parameters params = {
      .name = "key2nexthop",
      .entries = 16,
      .bucket_entries = RTE_HASH_BUCKET_ENTRIES_MAX,
      .key_len = 4,
      .hash_func = rte_jhash,
      .hash_func_init_val = seed,
      .socket_id = (int) rte_socket_id()
    };

    route_table->key2nexthop = rte_hash_create(&params);

    if(route_table->key2nexthop == NULL){
        printf("cannot create hash table\n");
        return 1;
    }

    add_staticroute(route_table);

    //lookup test
    printf("lookup test : 10.10.1.0\n");
    struct in_addr addr;
    uint32_t ipaddr;
    uint8_t key = 0;

    inet_aton("10.10.1.0", &addr);
    ipaddr = ntohl(addr.s_addr);
    if(rte_lpm_lookup(route_table->lpm, ipaddr, &key) != 0)
        printf("lookup error\n");
//    printf("nexthop : %u\n", port2ip[key][0]);
    addr.s_addr = htonl(port2ip[key][0]);
    printf("nexthop : %s\n", inet_ntoa(addr));
    return 0;
}
