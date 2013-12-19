#include "sysinclude.h"
#pragma pack (1)
#define WAIT_TIME 10

#define FLAG_DATA 0x00
#define FLAG_SYN 0x02
#define FLAG_FIN 0x01
#define FLAG_ACK 0x10

extern void tcp_DiscardPkt(char* pBuffer, int type);
extern void tcp_sendReport(int type);
extern void tcp_sendIpPkt(unsigned char* pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8  ttl);
extern int waitIpPacket(char *pBuffer, int timeout);
extern unsigned int getIpv4Address();
extern unsigned int getServerIpv4Address();

#define INPUT 0
#define OUTPUT 1

#define MAX_TCP_CONNECTIONS 5

int LOCALPORT = 2007;
int REMOTEPORT = 2006;
int SEG_NUM = 1234;
int ACK_NUM = 0;

enum TCP_STATES {
	CLOSED,
	SYN_SENT,
	ESTABLISHED,
	FIN_WAIT1,
	FIN_WAIT2,
	TIME_WAIT,
};

struct TCP_SEG {
	UINT16 src_port;
	UINT16 dst_port;
	UINT32 seq_num;
	UINT32 ack_num;
	UINT8 hdr_len;
	UINT8 flags;
	UINT16 window_size;
	UINT16 checksum;
	UINT16 urg_ptr;
	unsigned char data[4096];
	unsigned short len;
};

struct TCB {
	TCP_STATES current_state;
	UINT32 local_ip;
	UINT16 local_port;
	UINT32 remote_ip;
	UINT16 remote_port;
	UINT32 seq;
	UINT32 ack;
	UINT8 flags;
	int iotype;
	int is_used;
	unsigned char data[4096];
	unsigned short data_len;
};

struct TCB tcbs[MAX_TCP_CONNECTIONS];
int initialized = 0;

unsigned short tcp_calc_checksum(struct TCB* pTcb, struct TCP_SEG* pTcpSeg) {
	int len = pTcpSeg->len;
	UINT32 sum = 0;
	UINT16* p = (UINT16*)pTcpSeg;
	cout << len;
	while (len > 1) {
		sum += *p;
		p ++;
		len -= 2;
	}
	if (len) {
		UINT16 tmp = *((UINT8*)p);
		tmp = tmp << 8;
		sum += tmp;
	}
	// Pseudo Header

	UINT32 local_ip = htonl(pTcb->local_ip);
	UINT32 remote_ip = htonl(pTcb->remote_ip);
	sum = sum + (local_ip>>16) + (local_ip&0xffff) + (remote_ip>>16) + (remote_ip&0xffff);
	sum = sum + 0x0600 + ntohs(pTcpSeg->len);
	sum = ( sum & 0xFFFF ) + ( sum >> 16 );
	sum = ( sum & 0xFFFF ) + ( sum >> 16 );
	return (UINT16)(~sum);
}

int get_socket(unsigned short local_port, unsigned short remote_port) {
	for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
		if (tcbs[i].is_used == 1 && tcbs[i].local_port == local_port && tcbs[i].remote_port == remote_port) {
			return i;
		}
	}
	return -1;
}

int tcb_init(int sockfd) {
	if (tcbs[sockfd].is_used == 1) {
		return -1;
	} else {
		tcbs[sockfd].current_state = CLOSED;
		tcbs[sockfd].local_ip = getIpv4Address();
		tcbs[sockfd].local_port = LOCALPORT + sockfd;
		tcbs[sockfd].seq = SEG_NUM;
		tcbs[sockfd].ack = ACK_NUM;
		tcbs[sockfd].is_used = 1;
	}

	return 0;
}

void tcp_construct_segment(struct TCP_SEG* seg, struct TCB* tcb, unsigned short datalen, unsigned char* pData) {
	seg->src_port = tcb->local_port;
	seg->dst_port = tcb->remote_port;
	seg->seq_num = tcb->seq;
	seg->ack_num = tcb->ack;
	seg->hdr_len = (UINT8)(0x50);       //0x50=160
	seg->flags = tcb->flags;
	seg->window_size = 1024;
	seg->urg_ptr = 0;

	if(datalen > 0 && pData != NULL) {
		memcpy(seg->data, pData, datalen);
	}

	seg->len = 20 + datalen;
}

int tcp_send_seg(struct TCB* tcb, struct TCP_SEG* seg) {
	seg->src_port = htons(seg->src_port);
	seg->dst_port = htons(seg->dst_port);
	seg->seq_num = htonl(seg->seq_num);
	seg->ack_num = htonl(seg->ack_num);
	seg->window_size = htons(seg->window_size);
	seg->urg_ptr = htons(seg->urg_ptr);

	seg->checksum = 0;
	seg->checksum = tcp_calc_checksum(tcb, seg);


	tcp_sendIpPkt((unsigned char*)seg, seg->len, tcb->local_ip, tcb->remote_ip, 255);

	if( (tcb->flags & 0x0f) == FLAG_DATA) {
		tcb->seq += seg->len - 20;
	} else if( (tcb->flags & FLAG_SYN) == FLAG_SYN) {
		tcb->seq++;
	} else if( (tcb->flags & FLAG_FIN) == FLAG_FIN) {
		tcb->seq++;
	} else if( (tcb->flags & FLAG_ACK) == FLAG_ACK) {
	}
	return 0;
}

void process(struct TCB* tcb, struct TCP_SEG* tcp_seg) {
	struct TCP_SEG my_seg;
	cout << "!!! Current tcb state:" << tcb->current_state << endl;
	switch(tcb->current_state) {
		case CLOSED:
			tcb->current_state = SYN_SENT;
			tcb->seq = tcp_seg->seq_num ;
			tcp_send_seg(tcb, tcp_seg);
			break;

		case SYN_SENT:
			tcb->ack = tcp_seg->seq_num + 1;
			tcb->flags = FLAG_ACK;
			tcp_construct_segment( &my_seg, tcb, 0, NULL );
			tcp_send_seg( tcb, &my_seg );
			tcb->current_state = ESTABLISHED;
			break;

		case ESTABLISHED:
			cout << "!!!!" << tcp_seg->flags << endl;
			if( tcb->iotype == INPUT ) {

				tcb->data_len = tcp_seg->len - 20;
				if( tcb->data_len != 0 ) {
					memcpy(tcb->data, tcp_seg->data, tcp_seg->len - 20);

					tcb->ack += tcb->data_len;
					tcb->flags = FLAG_ACK;                                      //ACK=1
					tcp_construct_segment(&my_seg, tcb, 0, NULL);
					tcp_send_seg(tcb, &my_seg);                             //数据传输
				}
			} else {
				if( (tcp_seg->flags & FLAG_FIN) == FLAG_FIN) {                         //FIN=1
					tcb->current_state = FIN_WAIT1;
				}
				tcp_send_seg( tcb, tcp_seg );                                   //发送关闭连接请求
			}
			break;
		case FIN_WAIT1:
			if( (tcp_seg->flags & FLAG_ACK) == FLAG_ACK && tcp_seg->ack_num == tcb->seq ) {               //ACK=1, 验证ACK
				tcb->current_state = FIN_WAIT2;                                                   //收到应答
			}
			break;
		case FIN_WAIT2:
			if( tcp_seg->seq_num != tcb->ack ) {                                                  //验证序号
				tcp_DiscardPkt((char*)tcp_seg, STUD_TCP_TEST_SEQNO_ERROR);                        //序号不正确
			} else if( (tcp_seg->flags & FLAG_FIN) == FLAG_FIN) {
				tcb->ack++;
				tcb->flags = FLAG_ACK;
				tcp_construct_segment( &my_seg, tcb, 0, NULL );
				tcp_send_seg( tcb, &my_seg );
				tcb->current_state = CLOSED;
			}
			break;
		case TIME_WAIT:
			tcb->current_state = CLOSED;
			break;
	}
}

int stud_tcp_input(char* pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr) {
	struct TCP_SEG tcp_seg;
	memcpy(&tcp_seg, pBuffer, len);

	int sockfd = -1;
	if (initialized == 0) {
		tcb_init(0);
		tcbs[0].remote_ip = getServerIpv4Address();
		tcbs[0].remote_port = REMOTEPORT;
		initialized = 1;
	}
	sockfd = get_socket(ntohs(tcp_seg.dst_port), ntohs(tcp_seg.src_port));

	tcp_seg.len = len;

	if (len < 20 || tcp_calc_checksum(&tcbs[sockfd], &tcp_seg) != 0 ) {
		return -1;
	}

	tcp_seg.src_port = ntohs(tcp_seg.src_port);
	tcp_seg.dst_port = ntohs(tcp_seg.dst_port);
	tcp_seg.seq_num = ntohl(tcp_seg.seq_num);
	tcp_seg.ack_num = ntohl(tcp_seg.ack_num);
	tcp_seg.window_size = ntohs(tcp_seg.window_size);
	tcp_seg.checksum = ntohs(tcp_seg.checksum);
	tcp_seg.urg_ptr = ntohs(tcp_seg.urg_ptr);

	tcbs[sockfd].iotype = INPUT;
	memcpy(tcbs[sockfd].data, tcp_seg.data, len - 20);
	tcbs[sockfd].data_len = len - 20;

	process(&tcbs[sockfd], &tcp_seg);

	return 0;
}

void stud_tcp_output(char* pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr) {
	struct TCP_SEG my_seg;
	int sockfd = -1;

	if (initialized == 0) {
		tcb_init(0);
		tcbs[0].remote_ip = getServerIpv4Address();
		tcbs[0].remote_port = REMOTEPORT;
		initialized = 1;
	}
	sockfd = get_socket(srcPort, dstPort);
	tcbs[sockfd].flags = flag;
	tcp_construct_segment(&my_seg, &tcbs[sockfd], len, (unsigned char *)pData);
	tcbs[sockfd].iotype = OUTPUT;
	process(&tcbs[sockfd], &my_seg);
}

int stud_tcp_socket(int domain, int type, int protocol) {
	int sockfd = -1;

	for (int i=1; i<MAX_TCP_CONNECTIONS; i++ ) {
		if( tcbs[i].is_used == 0) {
			sockfd = i;

			if (tcb_init(sockfd) == -1 ) {
				return -1;
			}
			break;
		}
	}
	initialized = 1;
	return sockfd;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in* addr, int addrlen) {
	char buffer[2048];
	int len;

	tcbs[sockfd].remote_ip = ntohl(addr->sin_addr.s_addr);
	tcbs[sockfd].remote_port = ntohs(addr->sin_port);
	stud_tcp_output( NULL, 0, FLAG_SYN, tcbs[sockfd].local_port, tcbs[sockfd].remote_port, tcbs[sockfd].local_ip, tcbs[sockfd].remote_ip);

	len = waitIpPacket(buffer, WAIT_TIME);
	if (stud_tcp_input(buffer, len, htonl(tcbs[sockfd].remote_ip), htonl(tcbs[sockfd].local_ip))){
		return -1;
	}
	return 0;
}

int stud_tcp_send(int sockfd, const unsigned char* pData, unsigned short datalen, int flags) {
	char buffer[2048];
	int len;

	if( tcbs[sockfd].current_state != ESTABLISHED ) {
		return -1;
	}

	stud_tcp_output((char *)pData, datalen, flags, tcbs[sockfd].local_port, tcbs[sockfd].remote_port, tcbs[sockfd].local_ip, tcbs[sockfd].remote_ip);
	len = waitIpPacket(buffer, WAIT_TIME);
	stud_tcp_input(buffer, len, htonl(tcbs[sockfd].remote_ip), htonl(tcbs[sockfd].local_ip));
	return 0;
}

int stud_tcp_recv(int sockfd, unsigned char* pData, unsigned short datalen, int flags) {
	char buffer[2048];
	int len;

	if( (len = waitIpPacket(buffer, WAIT_TIME)) < 20 ) {
		return -1;
	}

	stud_tcp_input(buffer, len, htonl(tcbs[sockfd].remote_ip), htonl(tcbs[sockfd].local_ip));
	memcpy(pData, tcbs[sockfd].data, tcbs[sockfd].data_len);
	return tcbs[sockfd].data_len;
}

int stud_tcp_close(int sockfd) {
	char buffer[2048];
	int len;
	stud_tcp_output(NULL, 0, FLAG_FIN | FLAG_ACK, tcbs[sockfd].local_port, tcbs[sockfd].remote_port, tcbs[sockfd].local_ip, tcbs[sockfd].remote_ip);

	if( (len = waitIpPacket(buffer, WAIT_TIME)) < 20 ) {
		return -1;
	}
	stud_tcp_input(buffer, len, htonl(tcbs[sockfd].remote_ip), htonl(tcbs[sockfd].local_ip));

	if( (len = waitIpPacket(buffer, WAIT_TIME)) < 20 ) {
		return -1;
	}
	stud_tcp_input(buffer, len, htonl(tcbs[sockfd].remote_ip), htonl(tcbs[sockfd].local_ip));
	tcbs[sockfd].is_used = 0;
	return 0;
}
