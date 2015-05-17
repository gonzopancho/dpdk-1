#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_lpm.h>
#include <rte_hash.h>

#include "routetable.h"

extern uint32_t port2ip[4][2];

int add_staticroute(struct route_table *route_table){
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

    printf("reading interface\n");

    int i;
    for(i=0; i<4 ;i++){
        fgets(str, 50, fp);
        network = strtok(str," ");  //ignore portXX
        network = strtok(NULL," ");
        inet_aton(network,&addr);
        netmask = strtok(NULL, " ");
        netmask = strtok(netmask, "\n");
        inet_aton(network,&addr);
        port2ip[i][0] = ntohl(addr.s_addr); 
        inet_aton(netmask,&addr);
        port2ip[i][1] = ntohl(addr.s_addr); 
    }

    fgets(str,20,fp);
    while(str[0] == '\n') 
        fgets(str, 20, fp);

    if(strcmp(str,"route\n") != 0){
        printf("invalid file format\n");
        return 1;
    }
    
    printf("reading route\n");

    while(fgets(str,60,fp) != NULL){
        network = strtok(str," ");
        netmask = strtok(NULL, " ");
        nexthop = strtok(NULL, " ");
        nexthop = strtok(nexthop, "\n");

        printf("network : %s\n", network);
        printf("netmask : %s\n", netmask);
        printf("nexthop : %s\n", nexthop);

        //make hash of nexthop
        inet_aton(nexthop,&addr);
        ipaddr = ntohl(addr.s_addr); 
        key = rte_hash_add_key(route_table->key2nexthop, &ipaddr); 

        //get depth from netmask
        inet_aton(netmask,&addr);
        ipaddr = ntohl(addr.s_addr); 
//        int i;
//        for(i=31; i>=0; i--)
//            if(ipaddr & (0x00000001 << i) == 0) break;
//        depth = 32-(i+1); 
        depth = 24; 

        //add route to lpm
        inet_aton(network,&addr);
        ipaddr = ntohl(addr.s_addr); 
        if(rte_lpm_add(route_table->lpm, ipaddr, depth, key) <= 0)
            printf("lpm_add failed\n\n");
    }


    fclose(fp);
    return 0;
}

