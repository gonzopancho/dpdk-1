#ifndef MARIOROUTE_ICMP_H
#define MARIOROUTE_ICMP_H

#include <netinet/ip_icmp.h>
#include <rte_ip.h>

/* calc chksum.
   length : byte length of data for checksum */
uint16_t calc_checksum(unsigned short *buf, int length);

/* generate an echo message from an ipv4 packet.
   i pv4 header field will not be changed */
int icmp_echo_reply(struct rte_mbuf *buf);

/* generate a time exceeded message from an ipv4 packet.
   original ipv4 header + first 64 bytes of the data will be copied to the data field */
int icmp_time_exceeded(struct rte_mbuf *buf);

 /* generate a destination unreachable message from an ipv4 packet.
 *  original ipv4 header + first 64 bytes of the data will be copied to the data field */
int icmp_destination_unreachable(struct rte_mbuf *buf, uint8_t code);

int icmp_in(struct rte_mbuf *buf);

#endif

