#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_lpm.h>
#include <rte_hash.h>
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
#include "arp.h"
#include "ipv4.h"
#include "icmp.h"
#include "routetable.h"
#include "packetdump.h"
#include "runtime.h"

#define RTE_LOGTYPE_ARP_TABLE RTE_LOGTYPE_USER1


extern uint32_t port2ip[4][2];
extern struct ether_addr port2eth[4];
extern struct arp_table *arp_table;
extern struct route_table *route_table;

struct arp_table*
create_arp_table(uint32_t _size)
{
  rte_srand((unsigned) time (NULL));
  uint32_t seed = (uint32_t) rte_rand();
  uint32_t size = (uint32_t) POWERROUND(_size);
  size = size > RTE_HASH_ENTRIES_MAX? RTE_HASH_ENTRIES_MAX : size;

  struct arp_table *table;
  table = (struct arp_table*) rte_malloc(NULL,
             sizeof(struct arp_table) + sizeof(struct arp_table_entry) * size, 0);
  if (table == NULL) {
    RTE_LOG( ERR, ARP_TABLE, "cannot allocate memory for table.\n");
    goto out;
  }
  
  struct rte_hash_parameters params = {
    .name = "arp_table",
    .entries = size,
    .bucket_entries = RTE_HASH_BUCKET_ENTRIES_MAX,
    .key_len = 4,
    .hash_func = rte_jhash,
    .hash_func_init_val = seed,
    .socket_id = (int) rte_socket_id()
  };
  table->handler = rte_hash_create(&params);
  if (table->handler == NULL) {
    RTE_LOG(ERR, ARP_TABLE,
            "cannot create rte_hash: %s.\n", rte_strerror(rte_errno));
    goto free;
  }

  return table;
free:
  rte_free(table->handler);
out:
  return NULL;  
}

void
destroy_arp_table(struct arp_table* table)
{
  rte_hash_free(table->handler);
  rte_free(table->items);
}

int
add_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr,
                    const struct ether_addr* addr)
{
  int32_t key = rte_hash_add_key(table->handler, ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    ether_addr_copy(addr, &entry->eth_addr);
    entry->ip_addr = *ip_addr;
    entry->expire = ARP_TABLE_EXPIRE_TIME;
    return 0;
  }

  if (key == -ENOSPC) {
    RTE_LOG(WARNING, ARP_TABLE, "no space in the hash for this key.\n");
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOSPC:
      RTE_LOG(WARNING, ARP_TABLE, "no space in the hash for this key.\n");
      /* break through */
  }
  return key;
}

int
remove_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr)
{
  int32_t key = rte_hash_del_key(table->handler, ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    ether_addr_copy((struct ether_addr*) &"000000", &entry->eth_addr);
    entry->ip_addr = 0;
    entry->expire = 0;
    
    return 0;
  }

  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOENT:
      RTE_LOG(WARNING, ARP_TABLE, "the key is not found.\n");
      /* break through */
  }
  return key;
}

struct arp_table_entry* 
lookup_arp_table_entry(struct arp_table* table, uint32_t *ip_addr)
{
  int32_t key = rte_hash_lookup(table->handler, (void*) ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    return entry;
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOENT:
      ;
      //RTE_LOG(WARNING, ARP_TABLE, "the key is not found.\n");
      /* break through */
  }
  return NULL;
}

int
lookup_bulk_arp_table_entries(struct arp_table *table,
                              const uint32_t **ip_addrs,
                              uint32_t num_entry,
                              struct arp_table_entry** entries)
{
  int32_t positions[num_entry];
  int res = rte_hash_lookup_bulk(table->handler, (const void**) ip_addrs,
                                 num_entry, (int32_t*) positions);
  if (res ==  0) {
    uint32_t i;
    for (i = 0; i < num_entry; i++) {
      // XXX: inline extraction 
      entries[i] = &table->items[positions[i]];
    }
    return 0;
  }
  
  RTE_LOG(ERR, ARP_TABLE, "error.\n");
  return res;
}

static int
arp_request_process(struct rte_mbuf* buf)
{
  int res;
  struct arp_hdr* arp_hdr;
  struct arp_ipv4* arp_data;
  struct ether_hdr*eth;

  arp_hdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  arp_data = &arp_hdr->arp_data;
  if (!is_my_ip(arp_data->arp_tip)) return -1;


  res = add_arp_table_entry(arp_table, &arp_data->arp_sip, &arp_data->arp_sha);
  if (res) {
    RTE_LOG(ERR, ARP_TABLE, 
            "No more space for arp table: Drop ARP request.\n");
    rte_pktmbuf_free(buf);
    return -2;
  }

  struct ether_addr tmp = arp_data->arp_tha;
  arp_data->arp_tha = arp_data->arp_sha;
  arp_data->arp_sha = tmp;
  uint32_t addr = arp_data->arp_tip;
  arp_data->arp_tip = arp_data->arp_sip;
  arp_data->arp_sip = addr;
  arp_hdr->arp_op = htons(ARP_OP_REPLY);
  
  eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  eth->d_addr = arp_data->arp_tha;
  eth->s_addr = arp_data->arp_sha;

  //no need to change buf->pkt_len

  return 0;
}

static int
arp_reply_process(struct rte_mbuf* buf)
{
  printf("arp_reply_process\n");

  int res;
  struct arp_hdr* arp_hdr;
  struct arp_ipv4* arp_data;
  struct ether_addr etheraddr;

  arp_hdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  arp_data = &arp_hdr->arp_data;
  rte_eth_macaddr_get(buf->port, &etheraddr);
 
  print_arp(arp_hdr); 
  if (is_same_ether_addr(&arp_data->arp_tha, &etheraddr) == 1){
    return -2;
  }
  
  printf("hoge1\n");
  res = add_arp_table_entry(arp_table, &arp_data->arp_sip, &arp_data->arp_sha);
  printf("hoge2\n");
  if (res) return -1;

  printf("arp_table updated\n");
  rte_pktmbuf_free(buf);
  return -2;
}

int
arp_in(struct rte_mbuf* buf)
{
  int res = 0;
  struct arp_hdr* arp_hdr;
  arp_hdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);

  switch(ntohs(arp_hdr->arp_op)) {
    case ARP_OP_REQUEST : {
      printf("arp_request\n");
      res = arp_request_process(buf);
      break;
    }
    case ARP_OP_REPLY : {
      printf("arp_reply\n");
      res = arp_reply_process(buf);      
      break;
    }
  }
  
  return res;
}

int
gen_arp_request(struct rte_mbuf* buf, uint8_t src_port) 
{
  struct arp_hdr* arp_hdr;
  struct arp_ipv4* arp_data;

  struct ipv4_hdr *ipv4_hdr;
  uint32_t addr;
  uint8_t key = 0;
  int port;

  ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  if(rte_lpm_lookup(route_table->lpm, ntohl(ipv4_hdr->dst_addr), &key) == -ENOENT){
    printf("lookup error\n");
    goto out;
  }
  addr = route_table->item[key];

  for(port=0; port<4; port++)
    if( (port2ip[port][0] & port2ip[port][1]) == (route_table->item[key] & port2ip[port][1]) )
      break;
  
  if(port == 4) goto out;

  arp_hdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  arp_data = &arp_hdr->arp_data; 

  arp_hdr->arp_hrd = htons(0x0001); //ethernet
  arp_hdr->arp_pro = htons(0x0800); //ip
  arp_hdr->arp_hln = 0x06;
  arp_hdr->arp_pln = 0x04;
  arp_hdr->arp_op = htons(ARP_OP_REQUEST);
  ether_addr_copy(&port2eth[port], &arp_data->arp_sha);
  arp_data->arp_sip = port2ip[port][0];
  int i;
  for(i=0; i<6; i++)
    arp_data->arp_tha.addr_bytes[i] = 0x00;
  arp_data->arp_tip = addr;

  print_arp(arp_hdr); 
  return port;

out:
  icmp_destination_unreachable(buf, 0);
  ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
  ipv4_hdr->src_addr = port2ip[src_port][0];
  ipv4_hdr->next_proto_id = 0x01; //icmp
  ipv4_hdr->time_to_live = 64; //icmp
  return -1;
}
