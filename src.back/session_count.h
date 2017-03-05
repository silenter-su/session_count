#ifndef _SESSION_COUNT_H_
#define _SESSION_COUNT_H_
#include <netinet/in.h>

typedef struct _IPHdr
{
	uint8_t ip_verhl;		/* version & header length */
	uint8_t ip_tos;			/* type of service */
	uint16_t ip_len;		/* datagram length */
	uint16_t ip_id;			/* identification */
	uint16_t ip_off;		/* fragment offset */
	uint8_t ip_ttl;			/* time to live field */
	uint8_t ip_proto;		/* datagram protlcol */
	uint16_t ip_csum;		/* cheksum */
	struct in_addr ip_src;	/* source IP */
	struct in_addr ip_dst;  /* dest IP */
} IPHdr;

void session_test();
void getPacket(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet);


#endif
