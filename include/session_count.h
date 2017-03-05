#ifndef _SESSION_COUNT_H_
#define _SESSION_COUNT_H_
#include <netinet/in.h>

/* ----------Globes---------- */
extern GHashTable*	g_hash_UDP;
extern GHashTable*	g_hash_ICMP;
extern uint16_t		g_total_num;
extern uint16_t		g_TCP_num;
extern uint16_t		g_UDP_num;
extern uint16_t		g_ICMP_num;

/* ---------- structural ---------- */
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

typedef struct _key
{
	unsigned short port_src;/* source port */
	unsigned short port_dst;/* dest port */
	unsigned int ip_src;    /* source IP */
	unsigned int ip_dst;    /* dest IP */
} key;

typedef struct _value
{
	struct	timeval arrived_time;
} value;

/* ---------- glib'hash table function ---------- */
void free_key(gpointer f_key);
void free_value(gpointer f_value);
gboolean IPEqualFunc (gconstpointer a,gconstpointer b);
void print_key_value(gpointer key, gpointer value ,gpointer user_data);

/* ---------- each protocol ---------- */
void is_TCP(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr);
void is_UDP(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr);
void is_ICMP(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr);
void is_other_protocol(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr);

/* ---------- other ---------- */
int session_count_init();
void getPacket(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet);

#endif
