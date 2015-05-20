
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>

#include "ipv4.h"
#include "arp.h"
#include "icmp.h"
#include "packetdump.h"
#include "routetable.h"

struct ether_addr port2eth[4];

extern uint32_t port2ip[4][2];
extern struct arp_table *arp_table;
extern struct route_table *route_table;

int
swap_ipaddr(struct rte_mbuf *buf){
  struct ipv4_hdr *ipv4_hdr;
  ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  uint32_t temp;

  temp = ipv4_hdr->src_addr;
  ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
  ipv4_hdr->dst_addr = temp;

  printf("total len : %d\n",ipv4_hdr->total_length);
  print_ipv4(ipv4_hdr, PRINT_DATA);
  printf("\n\n");

  return 0;
}

int
is_my_ip(uint32_t addr){
  int i;
  for(i=0; i<4; i++)
    if(port2ip[i][0] == addr) return 1;
  return 0;
}


static int
ip_routing(struct rte_mbuf *buf, uint8_t src_port)
{  
  printf("ip_routing---------------------\n\n");
  struct ipv4_hdr *ipv4_hdr;
  struct in_addr addr;
  uint8_t key = 100;

  ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);

  if(rte_lpm_lookup(route_table->lpm, ntohl(ipv4_hdr->dst_addr), &key) != 0){
    printf("lookup error\n");
    goto out;
  }

  addr.s_addr = route_table->item[key];
  printf("nexthop : %s\n\n", inet_ntoa(addr));

  int i;
  for(i=0; i<4; i++){
    if( (port2ip[i][0] & port2ip[i][1]) == (route_table->item[key] & port2ip[i][1]) )
      return i;  //return port number
  }

out:
  icmp_destination_unreachable(buf, 0);
  ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
  ipv4_hdr->src_addr = port2ip[src_port][0];
  ipv4_hdr->next_proto_id = 0x01; //icmp
  ipv4_hdr->time_to_live = 64;
  return -1;
}


int
ip_in(struct rte_mbuf *buf, uint8_t src_port)
{
  int res = 0;
  int port = 0;
  struct arp_table_entry *entry;

  struct ether_hdr *eth_hdr;
  eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);

  struct ipv4_hdr *ipv4_hdr;
  ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  
  buf->l3_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) * 4;
  (ipv4_hdr->time_to_live)--;


  if( is_my_ip(ipv4_hdr->dst_addr) ) {
    switch(ipv4_hdr->next_proto_id) {
      case IPPROTO_ICMP: {
        printf("icmp recved\n");
        res = icmp_in(buf);
        swap_ipaddr(buf);
        ipv4_hdr->hdr_checksum = 0;
        ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
        break;
      }
      case IPPROTO_TCP: {
        ;
        break;
      }
      case IPPROTO_UDP: {
        ;
        break;
      }
    }
  } 
  else {
    if((ipv4_hdr->time_to_live == 0)) {
      icmp_time_exceeded(buf);
      ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
      ipv4_hdr->src_addr = port2ip[src_port][0];
      ipv4_hdr->next_proto_id = 0x01; //icmp
      ipv4_hdr->fragment_offset = 0x0000; 
      ipv4_hdr->time_to_live = 64;
      ipv4_hdr->hdr_checksum = 0;
      ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
      print_ipv4(ipv4_hdr,1);
      return -1;
    }
    else{
      ipv4_hdr->hdr_checksum = 0;
      ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    }
  }
  
  printf("before----------------------------\n");
  print_ipv4(ipv4_hdr,1);

  if (res < 0) {  // if res is 1, packet already consumed.
    rte_pktmbuf_free(buf);
    return -1;
  }

  port = ip_routing(buf, src_port);  //return port number if no problem
  entry = lookup_arp_table_entry(arp_table, &ipv4_hdr->dst_addr);
 
  if(entry == NULL){
    port = gen_arp_request(buf, src_port);
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    eth_hdr->ether_type = htons(ETHER_TYPE_ARP);
    int i;
    for (i=0; i<6; i++)
      eth_hdr->d_addr.addr_bytes[i] = 0xff;
    printf("after----------------------------\n");
    print_arp( (struct arp_hdr*) ipv4_hdr);
  }
  else{
    ether_addr_copy(&entry->eth_addr, &eth_hdr->d_addr);
  }
 
  ether_addr_copy(&port2eth[port], &eth_hdr->s_addr);
  printf("port %u\n", port);
  print_eth(eth_hdr);

  return port;
}
