#ifndef _ANATOOL_H_H_
#define _ANATOOL_H_H_

#include <stdint.h>
#include <sys/types.h>

/*****************************************************/
#define Z_IP_TYPE 	0X0800
#define Z_ICMP_TYPE 0X01
#define Z_ICMPREQ_TYPE 0X08
#define Z_TCP_TYPE 0X06
#define Z_TCPSYN_TYPE 0X002


#define Z_MACHEAD_LEN 14	//MACHEAD LEN
#define Z_IPHEAD_SMALL_LEN 20

#define BUF_OFFSET(len , buf)	\
do{	\
	buf = buf + len;\
}while(0)

#define REMOVEMAC_OFFSET(buf)	\
do{	\
	BUF_OFFSET(Z_MACHEAD_LEN , buf);\
}while(0)

/*****************************************************/

typedef enum _ProtocolType
{
	E_ERROR_TYPE,
	E_UNKNOWN_TYPE,
	E_ICMPREQ_TYPE,
	E_ICMP_TYPE,
	E_TCP_TYPE,
	E_TCPSYN_TYPE
} proTypeE;

typedef struct _macHeadT{
	u_char d_mac[6];
	u_char s_mac[6];
	u_char ver[2];
} macHeadT;

typedef struct _ipHeadT{
	u_char ver_hdLen;
	u_char tos;
	uint16_t len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	u_char sip[4];
	u_char dip[4];
	void *opt;
} ipHeadT;

typedef struct _icmpHeadT{
	uint16_t tp_code;	//类型和代码
	uint16_t check;
}icmpHeadT;

typedef struct _tcpHeadT{
	uint8_t sport[2];
	uint8_t dport[2];
	uint32_t seq_no;
	uint32_t ack_no;
	u_char res_1:4;
	u_char th1:4;
	u_char flag:6;
	u_char res_2:2;

	/*...*/
}tcpHeadT;

/*****************************************************/
proTypeE z_judgeType_anaTool(uint64_t len, void *buf);

int z_removeIpHead_anaTool(uint64_t len, void **buf_ip);

int z_getSMAC_anaTool(uint64_t buflen, void *buf, u_char* s_mac, uint8_t len);
int z_getDMAC_anaTool(uint64_t buflen, void *buf, u_char* d_mac, uint8_t len);

#endif