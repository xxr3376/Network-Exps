#include "sysinclude.h"
#include <cstdio>
#pragma pack (1)

extern void bgp_FsmTryToConnectPeer();
extern void bgp_FsmSendTcpData(char *pBuf,DWORD dwLen);
#define BGP_version 4

#define BGP_error_message_header 1
#define BGP_error_open_message 2
#define BGP_error_update_message 3
#define BGP_error_keepalive_time 4
#define BGP_error_state 5

#define BGP_suberror_unsupported_version 1
#define BGP_suberror_bad_message_length 2
#define BGP_suberror_bad_message_type 3
#define BGP_suberror_unacceptable_hold_time 6

struct BGP_commonHead {
	UINT8 marker[16];
	UINT16 length;
	UINT8 type;
};
struct BGP_open {
	BGP_commonHead head;
	UINT8 version;
	UINT16 as;
	UINT16 holdtime;
	UINT32 id;
	UINT8 optParmLen;
};
struct BGP_notify {
	BGP_commonHead head;
	UINT8 errorcode;
	UINT8 subcode;
};
struct BGP_keepalive {
	BGP_commonHead head;
};
struct BGP_update {
	BGP_commonHead head;
};

void BGP_fillHeader(BGP_commonHead* header, UINT8 type, UINT16 length) {
	for (int i = 0; i < 16; i++ ) {
		header->marker[i] = 255;
	}
	header->length = htons(length);
	header->type = type;
}
void BGP_sendNotify(UINT8 errorcode, UINT8 subcodes) {
	BGP_notify* req = new BGP_notify;
	int size = sizeof(*req);
	BGP_fillHeader(&(req->head), BGP_NOTIFY, size);
	req->errorcode = errorcode;
	req->subcode = subcodes;
	bgp_FsmSendTcpData((char*)req, size);
	delete req;
}
void BGP_sendKeepalive() {
	BGP_keepalive* req = new BGP_keepalive;
	int size = sizeof(*req);
	BGP_fillHeader(&(req->head), BGP_KEEPALIVE, size);
	bgp_FsmSendTcpData((char*)req, size);
	delete req;
}
void BGP_sendOpen(BgpPeer *pPeer) {
	BGP_open* req = new BGP_open;
	int size = sizeof(*req);
	BGP_fillHeader(&(req->head), BGP_OPEN, size);
	req->version = 4;
	req->as = htons(pPeer->bgp_wMyAS);
	req->holdtime = htons(pPeer->bgp_dwCfgHoldtime);
	req->id = htonl(pPeer->bgp_dwMyRouterID);
	req->optParmLen = 0;
	bgp_FsmSendTcpData((char*)req, size);
	delete req;
}

BYTE stud_bgp_FsmEventOpen(BgpPeer *pPeer,BYTE *pBuf,unsigned int len) {
	BGP_commonHead *header = (BGP_commonHead*) pBuf;
	//check length
	//according to http://www.networksorcery.com/enp/protocol/bgp.htm
	UINT16 length = ntohs(header->length);
	if (length < 19 || length > 4096) {
		//error
		BGP_sendNotify(BGP_error_message_header, BGP_suberror_bad_message_length);
		pPeer->bgp_byState = BGP_STATE_IDLE;
		return -1;
	}
	// check version
	BGP_open *req = (BGP_open*) pBuf;
	if (req->version != BGP_version) {
		//error
		BGP_sendNotify(BGP_error_open_message, BGP_suberror_unsupported_version);
		pPeer->bgp_byState = BGP_STATE_IDLE;
		return -1;
	}
	//check holdtime
	UINT16 holdtime = ntohs(req->holdtime);
	if (holdtime == 1 || holdtime == 2) {
		BGP_sendNotify(BGP_error_open_message, BGP_suberror_unacceptable_hold_time);
		pPeer->bgp_byState = BGP_STATE_IDLE;
		return -1;
	}
	if (pPeer->bgp_byState == BGP_STATE_OPENSENT) {
		// this is right state
		BGP_sendKeepalive();
		// set a timer ???
		pPeer->bgp_byState = BGP_STATE_OPENCONFIRM;
	}
	else {
		//error, back to IDLE
		pPeer->bgp_byState = BGP_STATE_IDLE;
	}
	return 0;
}

BYTE stud_bgp_FsmEventKeepAlive(BgpPeer *pPeer,BYTE *pBuf,unsigned int len) {
	switch(pPeer->bgp_byState) {
		case BGP_STATE_IDLE:
		case BGP_STATE_CONNECT:
		case BGP_STATE_ACTIVE:
			pPeer->bgp_byState = BGP_STATE_IDLE;
			break;
		case BGP_STATE_OPENSENT:
			pPeer->bgp_byState = BGP_STATE_IDLE;
			break;
		case BGP_STATE_OPENCONFIRM:
			//restart Hold Timer. ???
			pPeer->bgp_byState = BGP_STATE_ESTABLISHED;
			break;
		case BGP_STATE_ESTABLISHED:
			//restart Hold Timer. ???
			BGP_sendKeepalive();
			break;
	}
	return 0;
}

BYTE stud_bgp_FsmEventNotification(BgpPeer *pPeer,BYTE *pBuf,unsigned int len) {
	pPeer->bgp_byState = BGP_STATE_IDLE;
	return 0;
}

BYTE stud_bgp_FsmEventUpdate(BgpPeer *pPeer,BYTE *pBuf,unsigned int len) {
	BGP_commonHead *header = (BGP_commonHead*) pBuf;
	if (pPeer->bgp_byState == BGP_STATE_ESTABLISHED) {
		//reset Hold Timer?
	}
	else {
		pPeer->bgp_byState = BGP_STATE_IDLE;
	}
	return 0;
}
#define BGP_TCP_CLOSE 1
#define BGP_TCP_FATAL_ERROR 2
#define BGP_TCP_RETRANSMISSION_TIMEOUT 3

BYTE stud_bgp_FsmEventTcpException(BgpPeer *pPeer,BYTE msgType) {
	switch(pPeer->bgp_byState)
	{
		case BGP_STATE_CONNECT:
			if(msgType == BGP_TCP_CLOSE || msgType == BGP_TCP_FATAL_ERROR) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			else if(msgType == BGP_TCP_RETRANSMISSION_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_ACTIVE;
			}
			break;
		case BGP_STATE_ACTIVE:
			if(msgType == BGP_TCP_CLOSE || msgType == BGP_TCP_FATAL_ERROR) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			break;
		case BGP_STATE_OPENSENT:
			if(msgType == BGP_TCP_CLOSE) {
				pPeer->bgp_byState = BGP_STATE_ACTIVE;
			}
			else if(msgType == BGP_TCP_FATAL_ERROR || msgType == BGP_TCP_RETRANSMISSION_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			break;
		case BGP_STATE_OPENCONFIRM:
		case BGP_STATE_ESTABLISHED:
			pPeer->bgp_byState = BGP_STATE_IDLE;
			break;
	}
	return 0;
}

BYTE stud_bgp_FsmEventTimerProcess(BgpPeer *pPeer,BYTE msgType) {
	switch(pPeer->bgp_byState)
	{
		case BGP_STATE_CONNECT:
			if(msgType == BGP_HOLD_TIMEOUT || msgType == BGP_KEEPALIVE_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			break;
		case BGP_STATE_ACTIVE:
			if(msgType == BGP_CONNECTRETRY_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_CONNECT;
				bgp_FsmTryToConnectPeer();
			}
			else if(msgType == BGP_HOLD_TIMEOUT || msgType == BGP_KEEPALIVE_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			break;
		case BGP_STATE_OPENSENT:
			pPeer->bgp_byState = BGP_STATE_IDLE;
			break;
		case BGP_STATE_OPENCONFIRM:
			if(msgType == BGP_CONNECTRETRY_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			else if(msgType == BGP_HOLD_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
				BGP_sendNotify(BGP_error_keepalive_time, 0);
			}
			else if(msgType == BGP_KEEPALIVE_TIMEOUT) {
				BGP_sendKeepalive();
			}
			break;
		case BGP_STATE_ESTABLISHED:
			if(msgType == BGP_CONNECTRETRY_TIMEOUT || msgType == BGP_HOLD_TIMEOUT) {
				pPeer->bgp_byState = BGP_STATE_IDLE;
			}
			else if(msgType == BGP_KEEPALIVE_TIMEOUT) {
				BGP_sendKeepalive();
			}
			break;
	}
	return 0;
}

BYTE stud_bgp_FsmEventStart(BgpPeer *pPeer) {
	if (pPeer->bgp_byState == BGP_STATE_IDLE) {
		pPeer->bgp_byState = BGP_STATE_CONNECT;
		bgp_FsmTryToConnectPeer();
	}
	return 0;
}

BYTE stud_bgp_FsmEventStop(BgpPeer *pPeer) {
	pPeer->bgp_byState = BGP_STATE_IDLE;
	return 0;
}

BYTE stud_bgp_FsmEventConnect(BgpPeer *pPeer) {
	switch(pPeer->bgp_byState)
	{
		case BGP_STATE_CONNECT:
		case BGP_STATE_ACTIVE:
			BGP_sendOpen(pPeer);
			pPeer->bgp_byState=BGP_STATE_OPENSENT;
			break;
		case BGP_STATE_OPENSENT:
		case BGP_STATE_OPENCONFIRM:
		case BGP_STATE_ESTABLISHED:
			pPeer->bgp_byState = BGP_STATE_IDLE;
			break;
	}
	return 0;
}
