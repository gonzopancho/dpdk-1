#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_random.h>
#include <rte_malloc.h>
#include <rte_lcore.h>


#include "routetable.h"

extern uint32_t port2ip[4][2];

struct route_table*
create_route_table(uint32_t size){
  struct route_table *table = (struct route_table*) rte_malloc(NULL,
				sizeof(struct route_table) + sizeof(uint32_t)*size, 0);
  table->lpm = rte_lpm_create("route_table", rte_socket_id(), size, 0);

  if(table->lpm == NULL){
      printf("cannot create lpm table\n");
      return NULL;
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

  table->nexthop2key = rte_hash_create(&params);

  if(table->nexthop2key == NULL){
      printf("cannot create hash table\n");
      return NULL;
  }

  printf("create_route_table-------------------\n");
  printf("&route_table : %p\n",table);
  printf("&lpm         : %p\n",table->lpm);
  printf("&key2nexthop : %p\n",table->nexthop2key);
  return table;
}

int add_staticroute(struct route_table *route_table){

  printf("add_staticroute-------------------\n");
  printf("&route_table : %p\n",route_table);
  printf("&lpm         : %p\n",route_table->lpm);
  printf("&key2nexthop : %p\n",route_table->nexthop2key);



    char str[60];
    char *network, *netmask, *nexthop;
    struct in_addr addr;
    uint32_t ipaddr;
    uint8_t depth;
    uint8_t key;

    FILE *fp = fopen("./routes.txt","r");
    if(fp==NULL){
        printf("cannot open a file\n");
        return 1;
    }

    printf("file open\n");

    fgets(str,20,fp);
    while(str[0] == '\n') 
        fgets(str, 20, fp);

    if(strcmp(str,"interface\n") != 0){
        printf("invalid file format\n");
        return 1;
    }

    printf("reading interface-------------------------\n\n");

    int i;
    for(i=0; i<4 ;i++){
        fgets(str, 50, fp);
        network = strtok(str," ");  //ignore portXX
        network = strtok(NULL," ");
        inet_aton(network,&addr);
        netmask = strtok(NULL, " ");
        netmask = strtok(netmask, "\n");
        inet_aton(network,&addr);
        port2ip[i][0] = addr.s_addr; 
        inet_aton(netmask,&addr);
        port2ip[i][1] = addr.s_addr; 
        printf("port%d:\n",i);
        printf("addr : %s\n",network);
        printf("mask : %s\n\n",netmask);
    }

    fgets(str,20,fp);
    while(str[0] == '\n') 
        fgets(str, 20, fp);

    if(strcmp(str,"route\n") != 0){
        printf("invalid file format\n");
        return 1;
    }
    
    printf("reading route----------------------------\n\n");

    while(fgets(str,60,fp) != NULL){
        network = strtok(str," ");
        netmask = strtok(NULL, " ");
        nexthop = strtok(NULL, " ");
        nexthop = strtok(nexthop, "\n");

        printf("network : %s\n", network);
        printf("netmask : %s\n", netmask);
        printf("nexthop : %s\n", nexthop);

        printf("\n");

        //make hash of nexthop
        inet_aton(nexthop,&addr);
        ipaddr = addr.s_addr; 
        printf("nexthop : %x\n", ipaddr);
        key = rte_hash_add_key(route_table->nexthop2key, &ipaddr); 
        route_table->item[key] = ipaddr;

        //get depth from netmask
        inet_aton(netmask,&addr);
        ipaddr = addr.s_addr; 
        printf("netmask : %x\n", ipaddr);
//        int i;
//        for(i=31; i>=0; i--)
//            if(ipaddr & (0x00000001 << i) == 0) break;
//        depth = 32-(i+1); 
        depth = 24; 

        //add route to lpm
        inet_aton(network,&addr);
        ipaddr = addr.s_addr; 
        printf("network : %x\n", ipaddr);
        printf("depth   : %u\n", depth);
        printf("key     : %u\n", key);
        printf("nexthop : %x\n", route_table->item[key]);
        if(rte_lpm_add(route_table->lpm, ntohl(ipaddr), depth, key) < 0)
            printf("lpm_add failed\n\n");
    }


    fclose(fp);
    return 0;
}

