#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include "session_count.h"

void session_test()
{
	printf("THIS IS A TEST OF SESSION_COUNT!!!\n");
}

void getPacket(u_char * arg,const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int * id = (int *)arg;

	printf("id: %d\n",++(*id));
	printf("Packet length: %d\n",pkthdr->len);
	printf("Number of bytes: %d\n",pkthdr->caplen);
	printf("Recieved time: %s\n",ctime((const time_t *)&pkthdr->ts.tv_sec));

	int i;
	for(i = 0; i < pkthdr->len; ++i)
	{
		printf(" %02x",packet[i]);
		if( (i + 1) % 16 == 0)
		{
			printf("\n");
		}
	}
	printf("\n\n");
}

void main ()
{
	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
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
	pcap_loop(device, -1,getPacket,(u_char*)&id);

	pcap_close(device);

	return;
}
