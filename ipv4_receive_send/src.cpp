/*
* THIS FILE IS FOR IP TEST
*/
// system support

#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

unsigned short int calcChecksum(char *buffer, unsigned short length) {
	unsigned short int *headi = (unsigned short int*)buffer;
	int count = length * 2;
	unsigned int sum = 0;
	while (count > 0) {
		sum += *headi;
		headi ++;
		count --;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return ~sum;
}
int stud_ip_recv(char *pBuffer,unsigned short length)
{
	int version = pBuffer[0]>>4;
	int headlength = pBuffer[0] & 0x0f;
	unsigned char ttl = (unsigned char)pBuffer[8];
	unsigned short int headerChecksum=(*(short unsigned int*)(pBuffer + 10));

	if (version != 4) {
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_VERSION_ERROR);
		return 1;
	}
	if (headlength < 5 | headlength > 15) {
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_HEADLEN_ERROR);
		return 1;
	}
	if (ttl == 0) {
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_TTL_ERROR);
		return 1;
	}
	if (calcChecksum(pBuffer, length) != 0) {
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_CHECKSUM_ERROR);
		return 1;
	}

	int destinationAddress = ntohl(*(unsigned int*)(pBuffer + 16));
	if (destinationAddress != getIpv4Address() && destinationAddress != 0xffffff) {
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}
	ip_SendtoUp(pBuffer , length);
	return 0;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	char *sendBuffer=(char*)malloc(len + 20);
	memset(sendBuffer,0,len+20);
	sendBuffer[0]=0x45;
	unsigned short int totallen=htons(len+20);
	memcpy(&sendBuffer[2],&totallen,2);
	sendBuffer[8]=ttl;
	sendBuffer[9]=protocol;
	unsigned int src=htonl(srcAddr);
	unsigned int des=htonl(dstAddr);
	memcpy(&sendBuffer[12],&src,4);
	memcpy(&sendBuffer[16],&des,4);

	unsigned short int checksum = calcChecksum(sendBuffer, 5);
	memcpy(&sendBuffer[10],&checksum,2);

	memcpy(&sendBuffer[20],pBuffer,len);
	ip_SendtoLower(sendBuffer,len+20);
	return 0;
}
