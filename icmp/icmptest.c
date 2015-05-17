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

#include "icmp.h"
#include "packetdump.h"

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192
#define ICMPDATASIZE 64

struct rte_mempool *mbuf_pool = NULL;

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

    //set ip header
    struct rte_mbuf *buf;
    buf = rte_pktmbuf_alloc(mbuf_pool);


    struct ipv4_hdr* ipv4_hdr;
    ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    struct in_addr addr;

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
    inet_aton("10.0.0.2", &addr);
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

    //for debug
    printf("for debug--------------------------\n");
    printf("&iphdr           : %p\n", ipv4_hdr);
    printf("sizeof(ipv4_hdr) : %ld\n",sizeof(struct ipv4_hdr));
    printf("&icmphdr         : %p\n", icmp_hdr);
    printf("sizeof(icmp_hdr) : %ld\n",sizeof(struct icmphdr));
    printf("&icmpdata        : %p\n", data);
    printf("icmpdata         : %s\n", data);
    printf("\n\n");

    //info of before-calcchksum pkt
    printf("icmphdr_before_calcchksum\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    //info of after-calcchksum pkt
    icmp_hdr->checksum=calc_checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr) + ICMPDATASIZE);
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    printf("icmphdr_after_calcchksum\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    //info of after-reply-processing pkt
    icmp_echo_reply(buf);
    //swap
    uint32_t temp;
    temp = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = temp;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    printf("icmphdr_after_reply_function\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    //for debug   ip_header_dump
    print_ipv4_hex(ipv4_hdr, 64);

    //info of after-time_exceeded--processing pkt
    icmp_time_exceeded(buf);
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    printf("icmphdr_after_timeexceeded_function\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    //info of after-destination_unreachabl3--processing pkt
    icmp_destination_unreachable(buf, 1);
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    printf("icmphdr_after_destination-unreachable_function\n");
    print_ipv4(ipv4_hdr, PRINT_DATA);
    printf("\n\n");

    rte_pktmbuf_free(buf);
    return 0;
}
