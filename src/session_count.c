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
#define HASH_BUF 128

/* ----------Data types---------- */ 

/* ----------Externs---------- */

/* ----------Globes---------- */
GHashTable*		g_hash_UDP = NULL;
GHashTable*		g_hash_ICMP = NULL;
GHashTable*		g_hash = NULL;
uint32_t		local_net_ip = 0;
uint16_t		g_total_num = 0;
uint16_t		g_TCP_num = 0;
uint16_t		g_UDP_num = 0;
uint16_t		g_ICMP_num = 0;
uint32_t		g_UDP_total = 0;
/* ---------- glib'hash table function ---------- */
guint g_ip_hash(gconstpointer v)
{
	char buf[HASH_BUF];
	memset(buf,0,HASH_BUF);
	key *p = (key*)v;	
	sprintf(buf,"%d%d%d%d",p->port_src,p->port_dst,p->ip_src,p->ip_dst);
	return g_str_hash((gconstpointer)buf);
}

void free_key(gpointer f_key)
{
	if(!f_key) //replace NULL;
	{
		printf("free_key parameter NULL!!!\n");
		return;
	}
	key* tmp_key = (key*)f_key;
	g_free(tmp_key);
	f_key = NULL;
}

void free_value(gpointer f_value)
{
	if(!f_value)
	{
		printf("free_value parameter NULL!!!\n");
		return;
	}
	value* tmp_value = (value*)f_value;
	g_free(tmp_value);
	f_value = NULL;
}

gboolean IPEqualFunc (gconstpointer a,gconstpointer b)
{
	if(!a || !b)
	{
		printf("IPEqualFunc parameter NULL!!!\n");
	}
	
	key *tmp_key_a = (key*)a;
	key *tmp_key_b = (key*)b;
		
	if(!memcmp(tmp_key_a,tmp_key_b,sizeof(key)));
	{
		return TRUE;
	}
	return FALSE;

}

void print_key_value(gpointer p_key, gpointer p_value ,gpointer user_data)
{
		if(!p_key || !p_value)
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
	g_UDP_total++;
	value* ret = NULL;
	key* tmp_key = NULL;
	value* tmp_value = NULL;
	if(!(tmp_key = (key*)g_try_malloc0(sizeof(key))) || !(tmp_value = (value*)g_try_malloc0(sizeof(value))))
	{
		printf("is_UDP temp key or value calloc failed!\n");
	}

	
	tmp_key->ip_src = ip_hdr->ip_src.s_addr;
	tmp_key->ip_dst = ip_hdr->ip_dst.s_addr;
	tmp_key->port_src = udp_hdr->uh_sport;
	tmp_key->port_dst = udp_hdr->uh_dport;

	gettimeofday(&tmp_value->arrived_time,NULL);

	if(!(ret = g_hash_table_lookup(g_hash_UDP,(gpointer)tmp_key)))
	{
		/* lock */
		g_hash_table_replace(g_hash_UDP,(gpointer)tmp_key,(gpointer)tmp_value);
		g_UDP_num++;
		/* unlock */
	}
	else
	{
		if((tmp_value->arrived_time.tv_sec - ret->arrived_time.tv_sec) >= TIME_OUT)
		{
			/* lock */
			g_hash_table_insert(g_hash_UDP,(gpointer)tmp_key,(gpointer)tmp_value);
			g_UDP_num++;
			/* unlock */
		}
		else
		{
			g_hash_table_insert(g_hash_UDP,(gpointer)tmp_key,(gpointer)tmp_value);
		}
	}
	printf("g_hash_UDP size is %d.\n",g_hash_table_size (g_hash_UDP));
	g_hash_table_foreach (g_hash_UDP,print_key_value,"each key/value:\n");

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
	g_hash_UDP = g_hash_table_new_full(g_ip_hash,IPEqualFunc,free_key,free_value);
	g_hash_ICMP = g_hash_table_new_full(g_ip_hash,IPEqualFunc,free_key,free_value);
	if(!g_hash_UDP || !g_hash_ICMP)
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

void get_local_ip(const char* dev)
{
	pcap_if_t *alldevs;
	pcap_if_t *device;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	device = alldevs;
	for(; device != NULL; device = device->next)
	{
		printf("Device name: %s\n", device->name);
		printf("Description: %s\n", device->description);
	}
	/* 不再需要设备列表了，释放它 */
	pcap_freealldevs(alldevs);
	return; 
}

void main ()
{
	char errBuf[PCAP_ERRBUF_SIZE + 1], * devStr;//指针要不要释放.
	int ret = 0;

















	if(ret != session_count_init())
	{
		printf("session_count_init fail!!!\n");
		exit(1);
	}

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

	get_local_ip(devStr);

//	pcap_lookupnet(devStr,&local_net_ip,&net_mask,errBuf);
//	net_ip_address.s_addr = local_net_ip;
//	local_net_ip_string = inet_ntoa(net_ip_address);
//	printf("----------local_net_ip:%s-----------\n",local_net_ip_string);


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

	return;
}
