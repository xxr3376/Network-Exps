/*
* THIS FILE IS FOR IPv6 FORWARD TEST
*/
// system support

#include "sysinclude.h"
#include <vector>

// route table
vector<stud_ipv6_route_msg> routetable;

extern void ipv6_fwd_DiscardPkt(char *pBuffer, int type);
extern void ipv6_fwd_SendtoLower(char *pBuffer, int length, ipv6_addr *nexthop);
extern void getIpv6Address(ipv6_addr *pAddr);
extern void ipv6_fwd_LocalRcv(char *pBuffer, int length);

void stud_ipv6_Route_Init() {
    return;
}

void stud_ipv6_route_add(stud_ipv6_route_msg *proute) {
    routetable.push_back(*proute);
    return;
}

int stud_ipv6_fwd_deal(char *pBuffer, int length) {
    IPv6Head* ipv6packet = (IPv6Head*)pBuffer;
    if (ipv6packet->hopLimit == 0) {
        ipv6_fwd_DiscardPkt(pBuffer, STUD_IPV6_FORWARD_TEST_HOPLIMIT_ERROR);
        return 1;
    }
    ipv6_addr* hostaddr = (ipv6_addr*)malloc(sizeof(ipv6_addr));
    getIpv6Address(hostaddr);
    bool isequal = true;
    for (int i = 0; i < 4; i++) {
		isequal &= (ipv6packet->destAddr.dwAddr[i] == hostaddr->dwAddr[i]);
    }
    if (isequal) { //local
        ipv6_fwd_LocalRcv(pBuffer, length);
        return 0;
    }
    int mask = -1;
    ipv6_addr* nextAddr = (ipv6_addr*)malloc(sizeof(ipv6_addr));
	BYTE* dest = ipv6packet->destAddr.bAddr;
	for (int i = 0; i < routetable.size(); i++) {
		int currentmask = routetable[i].masklen;
		if (currentmask < mask)
			continue;
		isequal = true;
		int j = 0;
		BYTE* cur = routetable[i].dest.bAddr;
		while (currentmask > 8) {
			isequal &= (cur[j] == dest[j]);
			currentmask -= 8;
			j++;
		}
		int leftMask = 8 - currentmask;
		isequal &= ((cur[j] >> leftMask) == (dest[j] >> leftMask));
		if (!isequal)
			continue;
		mask = routetable[i].masklen;
		nextAddr = &(routetable[i].nexthop);
	}
    if (mask == -1) {
        ipv6_fwd_DiscardPkt(pBuffer, STUD_IPV6_FORWARD_TEST_NOROUTE);
        return -1;
    }
    ipv6packet->hopLimit -= 1;
    ipv6_fwd_SendtoLower(pBuffer, length, nextAddr);
    return 0;
}
