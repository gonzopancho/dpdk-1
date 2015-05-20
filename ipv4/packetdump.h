#ifndef MARIOROUTE_PKTDUMP_H
#define MARIOROUTE_PKTDUMP_H

#define DONT_PRINT_DATA 0
#define PRINT_DATA 1

#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <rte_ip.h>

/* print icmp packet
   wanna dump data field -> dispdataflag=PRINT_DATA */
int print_icmp(struct ipv4_hdr* ipv4_hdr, int dispdataflag);
//int print_tcp(struct ipv4_hdr* ipv4_hdr, int dispdataflag);
//int print_udp(struct ipv4_hdr* ipv4_hdr, int dispdataflag);

/* print ip packet
   wanna dump upper protocol (call print_{icmp,tcp,udp}) -> dispdataflag=PRINT_DATA */
int print_ipv4(struct ipv4_hdr* ipv4_hdr, int dispdataflag);

/* for debug
   print ip packet in hex
   len : byte length to dump */
int print_ipv4_hex(struct ipv4_hdr*, int len);

#endif

