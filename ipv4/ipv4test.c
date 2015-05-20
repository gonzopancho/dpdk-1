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

#include "icmp.h"
#include "ipv4.h"
#include "packetdump.h"
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


// init route_table
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

    route_table->nexthop2key = rte_hash_create(&params);

    if(route_table->nexthop2key == NULL){
        printf("cannot create hash table\n");
        return 1;
    }

    add_staticroute(route_table);

    //lookup test
    printf("lookup test : 10.10.2.1\n");
    struct in_addr addr;
    uint32_t ipaddr;
    uint8_t key = 0;

    inet_aton("10.10.2.1", &addr);
    ipaddr = ntohl(addr.s_addr);
    if(rte_lpm_lookup(route_table->lpm, ipaddr, &key) != 0)
      printf("lookup error\n");
//    printf("nexthop : %u\n", port2ip[key][0]);
    addr.s_addr = htonl(route_table->item[key]);
    printf("key : %d\n", key);
    printf("nexthop : %s\n", inet_ntoa(addr));


    //set ip header
    struct rte_mbuf *buf;
    buf = rte_pktmbuf_alloc(mbuf_pool);


    struct ipv4_hdr* ipv4_hdr;
    ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);

    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = 20 + sizeof(struct icmphdr) + ICMPDATASIZE;
    ipv4_hdr->packet_id = 1;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = 1;
    ipv4_hdr->hdr_checksum = 0;
    inet_aton("10.0.0.1", &addr);
    ipv4_hdr->src_addr=ntohl(addr.s_addr);
    inet_aton("10.10.10.2", &addr);
    ipv4_hdr->dst_addr=ntohl(addr.s_addr);

    //set icmp header
    uint8_t ipv4hdrlen = ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK;
    struct icmphdr* icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + ipv4hdrlen*4);
    char* data = (char*)icmp_hdr + sizeof(struct icmphdr);
    printf("enter icmp_data : ");
    fgets(data, ICMPDATASIZE, stdin);
    printf("\n\n");

    icmp_hdr->type=8;
    icmp_hdr->code=0;
    icmp_hdr->checksum=0;
    icmp_hdr->un.echo.id=0;
    icmp_hdr->un.echo.sequence=0;

    //info of after-calcchksum pkt
    icmp_hdr->checksum=calc_checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr) + ICMPDATASIZE);
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    printf("icmphdr_after_calcchksum\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    //info of ip_in
    int port;
    port = ip_in(buf);
    printf("icmphdr_after_ip_in\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    addr.s_addr = htonl(port2ip[port][0]);
    printf("port : %d\naddr : %s\n",port, inet_ntoa(addr));


    rte_pktmbuf_free(buf);
    return 0;
}
