#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include "icmp.h"



/* calc chksum.
 * length : byte length of data for checksum */
uint16_t calc_checksum(uint16_t *buf, int length)
{
    uint64_t sum;

    // checksum is calclated by 2 bytes
    for (sum=0; length>1; length-=2) 
        sum += *buf++;

    // for an extra byte
    if (length==1)
        sum += (char)*buf;

    // this can calc the 1's complement of the sum of each 1's complement
    sum = (sum >> 16) + (sum & 0xFFFF);  // add carry
    sum += (sum >> 16);          // add carry again
    return ~sum;
}

/*called from IP layer*/
int icmp_in(buf){
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    int ipv4hdrlen = ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK;
    struct icmphdr* icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + ipv4hdrlen*4);
    if(icmp_hdr->type == 8)
        icmp_echo_reply(buf)
    else{
        printf("unsupported type");
        return 1;
    }

    return 0;
}
    

/* generate an echo message from an ipv4 packet.
 * ipv4 header field will not be changed */
int icmp_echo_reply(struct rte_mbuf *buf)
{
    struct ipv4_hdr *ipv4_hdr;
    ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);

    /*  change the type code of the recieved packet and reculc the checksum */
    int ipv4hdrlen = ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK;
    int icmpdatalen = ipv4_hdr->total_length - iphdrlen*8 - sizeof(struct icmphdr); 
    struct icmphdr* icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + ipv4hdrlen*4);

    icmp_hdr->type = 0;
    icmp_hdr->checksum = calc_checksum((uint16_t*) icmp_hdr, icmpdatalen);
    return 0;
}


/* generate a time exceeded message from an ipv4 packet.
   original ipv4 header + first 64 bytes of the data will be copied to the data field */
int icmp_time_exceeded(struct rte_mbuf *buf)
{
    char* tempbuf;
    struct ipv4_hdr *ipv4_hdr;
    struct icmphdr *icmp_hdr;
    uint8_t ipv4hdrlen;


    ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    tempbuf = rte_malloc(NULL, ipv4_hdr->total_length, 0);
    rte_memcpy(tempbuf, ipv4_hdr, ipv4_hdr->total_length);
    ipv4hdrlen = ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK;
    icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + ipv4hdrlen*4);
    ipv4_hdr = (struct ipv4_hdr*) tempbuf;

    unsigned char* data;
    int data_len;

    // get ihl from "version + ihl"
    data = (unsigned char*)icmp_hdr + sizeof(struct icmphdr);

    icmp_hdr->type=11;
    icmp_hdr->code=0;  // 1(fragment reassembly time exceeded) is unsupported
    icmp_hdr->un.echo.id=0;
    icmp_hdr->un.echo.sequence=0;

    // data field = original IP header +  first 64 bits of the original data
    data_len = ipv4hdrlen*4 + 8;
    rte_memcpy(data, ipv4_hdr, data_len);

    icmp_hdr->checksum = calc_checksum((uint16_t*) icmp_hdr, data_len);
    rte_free(tempbuf);

    return 0;
}

/* generate a destination unreachable message from an ipv4 packet.
   original ipv4 header + first 64 bytes of the data will be copied to the data field */
int icmp_destination_unreachable(struct rte_mbuf *buf, uint8_t code)
{
    char* tempbuf;
    struct ipv4_hdr *ipv4_hdr;
    struct icmphdr *icmp_hdr;
    uint8_t ipv4hdrlen;


    ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    tempbuf = rte_malloc(NULL, ipv4_hdr->total_length, 0);
    rte_memcpy(tempbuf, ipv4_hdr, ipv4_hdr->total_length);
    ipv4hdrlen = ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK;
    icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + ipv4hdrlen*4);
    ipv4_hdr = (struct ipv4_hdr*) tempbuf;

    unsigned char* data;
    int data_len;

    // get ihl from "version + ihl"
    data = (unsigned char*)icmp_hdr + sizeof(struct icmphdr);

    icmp_hdr->type=3;
    icmp_hdr->code=code;  // 1(fragment reassembly time exceeded) is unsupported
    icmp_hdr->un.echo.id=0;
    icmp_hdr->un.echo.sequence=0;

    // data field = original IP header +  first 64 bits of the original data
    data_len = ipv4hdrlen*4 + 8;
    rte_memcpy(data, ipv4_hdr, data_len);

    icmp_hdr->checksum = calc_checksum((uint16_t*) icmp_hdr, data_len);
    rte_free(tempbuf);

    return 0;
}
