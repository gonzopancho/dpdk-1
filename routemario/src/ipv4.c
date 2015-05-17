/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

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

#include "util.h"
#include "ipv4.h"

static int
ip_routing(struct lcore_env *env, struct rte_mbuf *buf)
{  
  return 0;
}

int
ip_input(struct lcore_env *env, struct rte_mbuf *buf)
{
  int res = 0;
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  
  buf->l3_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) << 2;
  (iphdr->time_to_live)--;

  if(is_own_ip_addr(iphdr->dst_addr)) {
    switch(iphdr->next_proto_id) {
      case IPPROTO_ICMP: {
        res = icmp_input(env, buf);
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
  } else {
    if(!(iphdr->time_to_live > 0)) {
      send_icmp_time_exceeded(env, buf);
      return 0;
    }
  }
  
  if (res) {  // if res is 1, packet already consumed.
    rte_pktmbuf_free(buf);
    return 1;
  }

  ip_routing(env, buf, iphdr);  
  return 0;
}
