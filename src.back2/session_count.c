#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <glib.h>
#include "session_count.h"

/* ----------Macros---------- */

/* ----------Data types---------- */

/* ----------Externs---------- */

/* ----------Globes---------- */
GHashTable*		g_hash = NULL;
uint16_t		g_total_num = 0;
uint16_t		g_TCP_num = 0;
uint16_t		g_UDP_num = 0;
uint16_t		g_ICMP_num = 0;

void free_key(gpointer data)
{
	free(data);
}
void free_value(gpointer value)
{
	free(value);
}




void session_test()
{
	printf("THIS IS A TEST OF SESSION_COUNT!!!\n");
}

void getPacket(u_char * arg,const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
//	int * id = (int *)arg;
//
//	printf("id: %d\n",++(*id));
//	printf("Packet length: %d\n",pkthdr->len);
//	printf("Number of bytes: %d\n",pkthdr->caplen);
//	printf("Recieved time: %s\n",ctime((const time_t *)&pkthdr->ts.tv_sec));
//
//	int i;
//	for(i = 0; i < pkthdr->len; ++i)
//	{
//		printf(" %02x",packet[i]);
//		if( (i + 1) % 16 == 0)
//		{
//			printf("\n");
//		}
//	}
//	printf("\n\n");
	
	IPHdr *ip_hdr = NULL;
	ip_hdr = (IPHdr*)(packet + 14);
	
	switch(ip_hdr->ip_proto)
	{
		case IPPROTO_TCP:
			printf("TCP PACKET!!!!!!\n");
			break;
		case IPPROTO_UDP:
			printf("UDP PACKET!!!!!!\n");
			break;
		case IPPROTO_ICMP:
			printf("ICMP PACKET!!!!!!\n");
			break;
		default:
			printf("OTHER PACKET!!!!!!\n");
			break;
	}


}

void main ()
{
	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
	g_hash = g_hash_table_new_full(g_str_hash,g_str_equal,free_key,free_value);
	if(NULL == g_hash)
	{
		printf("Create hash table failed!!!\n");
	}

	//test
	g_hash_table_insert(g_hash, "Virginia", "Richmond");
	g_hash_table_insert(g_hash, "Texas", "Austin");
	g_hash_table_insert(g_hash, "Ohio", "Columbus");
	printf("There are %d keys in the hash\n", g_hash_table_size(g_hash));
	printf("The capital of Texas is %s\n", g_hash_table_lookup(g_hash, "Texas"));

	gboolean found = g_hash_table_remove(g_hash, "Virginia");
	printf("The value 'Virginia' was %sfound and removed\n", found ? "" : "not ");

	g_hash_table_destroy(g_hash);


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

//	/*wait a packet to arrive*/
//	struct pcap_pkthdr packet;
//	const u_char * pktStr = pcap_next(device,&packet);
//
//	if(!pktStr)
//	{
//		printf("did not capture a packet!\n");
//		exit(1);
//	}
//
//	printf("Packet length:%d\n",packet.len);
//	printf("Number of bytes:%d\n",packet.caplen);
//	printf("Recieved time:%s\n",ctime((const time_t *)&packet.ts.tv_sec));
//
//
//	session_test();

	/*wait loop forever */
	int id = 0;
	//pcap_loop(device, -1,getPacket,(u_char*)&id);

	pcap_close(device);

	return;
}
