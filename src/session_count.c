#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <glib.h>
#include <pthread.h>
#include "session_count.h"

/* ----------Macros---------- */
#define HASH_TOTAL 2
#define TIME_OUT 20 
#define MAC_HEAD_LEN 14
#define HEAD_STEP 4

/* ----------Data types---------- */ 

/* ----------Externs---------- */

/* ----------Globes---------- */
GHashTable*		g_hash_UDP = NULL;
GHashTable*		g_hash_ICMP = NULL;
GHashTable*		g_hash = NULL;
uint16_t		g_total_num = 0;
uint16_t		g_TCP_num = 0;
uint16_t		g_UDP_num = 0;
uint16_t		g_ICMP_num = 0;

/* ---------- glib'hash table function ---------- */
void free_key(gpointer f_key)
{
	if(NULL == f_key) //replace NULL;
	{
		printf("free_key parameter NULL!!!\n");
		return;
	}
	key* tmp_key = (key*)f_key;
	free(tmp_key);
	f_key = NULL;
}

void free_value(gpointer f_value)
{
	if(NULL == f_value)
	{
		printf("free_value parameter NULL!!!\n");
		return;
	}
	value* tmp_value = (value*)f_value;
	free(tmp_value);
	f_value = NULL;
}

gboolean IPEqualFunc (gconstpointer a,gconstpointer b)
{
	if(NULL == a || NULL == b)
	{
		printf("IPqualFunc parameter NULL!!!\n");
		return;
	}
	
	key *tmp_key_a = (key*)a;
	key *tmp_key_b = (key*)b;
		
	if(!memcmp(a,b,sizeof(key)));
				return TRUE;
	return FALSE;

}

void print_key_value(gpointer p_key, gpointer p_value ,gpointer user_data)
{
		if(NULL == p_key || NULL == p_value)
		{
			printf("printf_key_value parameter NULL!!!\n");
			return;
		}

		key* tmp_key;
		value* tmp_value;
		tmp_key	= (key*)p_key;
		tmp_value = (value*)p_value;

		printf("port_src = %d\n"
				"port_dst = %d\n"
				"ip_src	 = %d\n"
				"ip_dst	 = %d\n\n"
				"arrived_time->sec = %d\n" 
				"arrived_time->usec = %d\n" 
				,tmp_key->port_src 
				,tmp_key->port_dst 
				,tmp_key->ip_src 
				,tmp_key->ip_dst 
				,tmp_value->arrived_time.tv_sec 
				,tmp_value->arrived_time.tv_usec);
}

/* ---------- each protocol ---------- */
void is_TCP(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr)
{

}

void is_UDP(const struct pcap_pkthdr *pkthdr,const IPHdr *ip_hdr, const UDPHdr *udp_hdr)
{
	value* ret = NULL;
	key* tmp_key = NULL;
	value* tmp_value = NULL;
	if(!(tmp_key = (key*)calloc(1,sizeof(key))) || !(tmp_value = (value*)calloc(1,sizeof(value))))
	{
		printf("is_UDP temp key or value calloc failed!\n");
	}

	
	tmp_key->ip_src = ip_hdr->ip_src.s_addr;
	tmp_key->ip_dst = ip_hdr->ip_dst.s_addr;
	tmp_key->port_src = udp_hdr->uh_sport;
	tmp_key->port_dst = udp_hdr->uh_dport;

	gettimeofday(&tmp_value->arrived_time,NULL);

	if(!(ret = g_hash_table_lookup(g_hash_UDP,(gpointer)&tmp_key)))
	{
		/* lock */
		g_hash_table_insert(g_hash_UDP,(gpointer)&tmp_key,(gpointer)&tmp_value);
		g_UDP_num++;
		/* unlock */
	}
	else
	{
		if((tmp_value->arrived_time.tv_sec - ret->arrived_time.tv_sec) >= TIME_OUT)
		{
			/* lock */
			g_hash_table_insert(g_hash_UDP,(gpointer)&tmp_key,(gpointer)&tmp_value);
			g_UDP_num++;
			/* unlock */
		}
		else
		{
			g_hash_table_insert(g_hash_UDP,(gpointer)&tmp_key,(gpointer)&tmp_value);
		}
	}
	printf("----------%d----------\n",g_UDP_num);


}

void is_ICMP(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr)
{

}

void is_other_protocol(const struct pcap_pkthdr * pkthdr, const IPHdr *ip_hdr)
{

}

/* ---------- other ---------- */
int session_count_init()
{
	int tmp = 0;
	g_hash_UDP = g_hash_table_new_full(g_direct_hash,IPEqualFunc,free_key,free_value);
	g_hash_ICMP = g_hash_table_new_full(g_direct_hash,IPEqualFunc,free_key,free_value);
	if(NULL == g_hash_UDP || NULL == g_hash_ICMP)
	  return 1;
	/* creat & init the hash table mutex */
	/* creat pthred for manage the each hash table */
	//if(tmp = pthread_create(&
	return 0;
}
void getPacket(u_char * arg,const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	IPHdr *ip_hdr = NULL;
	ip_hdr = (IPHdr*)(packet + MAC_HEAD_LEN);

	
	switch(ip_hdr->ip_proto)
	{
		case IPPROTO_TCP:
			is_TCP(pkthdr,ip_hdr);
			break;
		case IPPROTO_UDP:
			{
				UDPHdr* udp_hdr;
				udp_hdr = (UDPHdr*)(packet + MAC_HEAD_LEN + (HEAD_STEP * (ip_hdr->ip_verhl & 0xf))); /*get UDP header right place*/
				//printf("主机字节序:%u\n",htons(udp_hdr->uh_dport));
				is_UDP(pkthdr,ip_hdr,udp_hdr);
			}
			break;
		case IPPROTO_ICMP:
			is_ICMP(pkthdr,ip_hdr);
			break;
		default:
			is_other_protocol(pkthdr,ip_hdr);
			break;
	}
}

void main ()
{
	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
	int ret = 0;
	if(ret = session_count_init())
	{
		printf("session_count_init fail!!!\n");
		exit(1);
	}

//	g_hash = g_hash_table_new_full(g_direct_hash,IPEqualFunc,free_key,free_value);
//	if(NULL == g_hash)
//	{
//		printf("Create hash table failed!!!\n");
//	}
//
//	key hash_key;
//	value hash_value;
//	memset(&hash_key,0,sizeof(key));
//	memset(&hash_value,0,sizeof(value));
//
//	hash_key.port_src = 1;
//	hash_key.port_dst = 2;
//	hash_key.ip_src = 3;
//	hash_key.ip_dst = 4;
//
//	hash_value.arrived_time.tv_sec = 5678;
//	hash_value.arrived_time.tv_usec = 1234567890;
//
//	g_hash_table_insert(g_hash,(gpointer)&hash_key,(gpointer)&hash_value);
//	printf("Hash size:%d\n", g_hash_table_size(g_hash));
//	g_hash_table_foreach(g_hash,print_key_value,NULL);
//
//	value* return_val = NULL;
//	return_val = g_hash_table_lookup(g_hash,(gpointer)&hash_key);
//
//	printf("return_val->arrived_time.tv_sec = %d\n"
//			"return_val->arrived_time.tv_usec = %d\n"
//			,return_val->arrived_time.tv_sec
//			,return_val->arrived_time.tv_usec);







	devStr = pcap_lookupdev(errBuf);
	if(devStr)
	{
		printf("success:device:%s\n",devStr);
	}
	else
	{
		printf("error: %s\n",errBuf);
		exit(1);
	}

	/*open a device,wait until a packet arrives*/
	pcap_t * device = pcap_open_live(devStr,65535,1,0,errBuf);
	if(!device)
	{
		printf("error:pcap_open_live(): %s\n",errBuf);
		exit(1);
	}

	/*wait loop forever */
	int id = 0;
	pcap_loop(device, -1,getPacket,(u_char*)&id);

	pcap_close(device);
//	g_hash_table_destroy(g_hash);

	return;
}
