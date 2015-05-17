#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ip.h>

#include "packetdump.h"

int print_icmp(struct ipv4_hdr* ipv4_hdr, int dispdataflag){
    static const char* icmp_type[] = {
        "Echo Reply",
        "undefined",
        "undefined",
        "Destination Unreachable",
        "Source Quench",
        "Ridirect",
        "undefined",
        "undefined",
        "Echo Request",
        "Router Advertisement",
        "Router Selection",
        "Time Exceeded",
        "Parameter Problem on Datagram",
        "Timestamp Request",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply"
    };

    static const char* icmp_unreach_code[] = {
	"Network Unreachable",
	"Host Unreachable",
	"Protocol Unreachable",
	"Port Unreachable",
	"Fragmentation Blocked",
	"Source Route Failed",
	"Destination Network Unknown",
	"Destination Host Unknown",
	"Source Host Isolate",
	"Destination Network Prohibited",
	"Destination Host Prohibited",
	"Network TOS Problem",
	"Host TOS Problem",
	"Communication administratively prohibited by filtering",
	"Host precedence violation",
	"Precedence cutoff in effect"
    };

    uint8_t iphdrlen = ipv4_hdr->version_ihl & 0x0f; 
    struct icmphdr* icmp_hdr = (struct icmphdr*) ((char*)ipv4_hdr + iphdrlen*4);
    uint16_t icmpdatalen = ipv4_hdr->total_length - iphdrlen*4 - sizeof(struct icmphdr);
    unsigned char* data = (unsigned char*)icmp_hdr + sizeof(struct icmphdr);

    printf("icmp----------------------------------\n");
    printf("icmp_type=%s\n", icmp_type[icmp_hdr->type]);
    if(icmp_hdr->type == 3)
        printf("icmp_code=%s\n", icmp_unreach_code[icmp_hdr->code]);
    else
        printf("icmp_code=0x%02x\n", icmp_hdr->code);
    printf("icmp_chksum=0x%02x\n", icmp_hdr->checksum);

    if(dispdataflag){
        printf("icmp_data--------------------------\n");
        int cnt=0;
        while(icmpdatalen > 0){
            printf("0x%02x ",*data++);
            if(cnt % 16 == 15) printf("\n");
            cnt++;
            icmpdatalen--;
        }
    }

    return 0;
} 

int print_ipv4(struct ipv4_hdr* ipv4_hdr, int dispdataflag){
    struct in_addr addr;

    printf("ip----------------------------------\n");
    printf("ip_version=0x%02x\n", (ipv4_hdr->version_ihl & 0xf0) >> 4);
    printf("ip_ihl=0x%02x\n", ipv4_hdr->version_ihl & 0x0f);
    printf("ip_tos=0x%02x\n", ipv4_hdr->type_of_service);
    printf("ip_totallength=0x%02x\n", ipv4_hdr->total_length);
    printf("ip_id=0x%02x\n", ipv4_hdr->packet_id);
    printf("ip_flags=0x%02x\n", (ipv4_hdr->fragment_offset & 0xe0) >> 13);
    printf("ip_fragentoffset=0x%02x\n", (ipv4_hdr->fragment_offset & 0x1f));
    printf("ip_ttl=0x%02x\n", ipv4_hdr->time_to_live);
    printf("ip_proto=0x%02x\n",  ipv4_hdr->next_proto_id);
    printf("ip_chksum=0x%02x\n", ipv4_hdr->hdr_checksum);
    addr.s_addr = htonl(ipv4_hdr->src_addr);
    printf("ip_src=0x%02x : %s\n", ipv4_hdr->src_addr, inet_ntoa(addr));
    addr.s_addr = htonl(ipv4_hdr->dst_addr);
    printf("ip_dst=0x%02x : %s\n", ipv4_hdr->dst_addr, inet_ntoa(addr));

    if(dispdataflag){
        if(ipv4_hdr->next_proto_id == 1) print_icmp(ipv4_hdr, PRINT_DATA);
//        else if(ipv4_hdr->next_proto_id == 6) 
//        else if(ipv4_hdr->next_proto_id == 17)
        else printf("upper protocol is unsupported\n");
    }
    printf("\n");

    return 0;
}

int print_ipv4_hex(struct ipv4_hdr* ipv4_hdr, int len){
    int cnt;
    unsigned char* data = (unsigned char*) ipv4_hdr;
    printf("ip_header_dump---------------------\n");
    for(cnt=0; cnt<len; cnt++){
        printf("0x%02x ",*data++);
        if(cnt % 16 == 15) printf("\n");
    }
    printf("\n\n");
    return 0;
}
