/*
	printf("MAC_D :%02X-%02X-%02X-%02X-%02X-%02X\n", pmyMac->d_mac[0], pmyMac->d_mac[1], pmyMac->d_mac[2], pmyMac->d_mac[3], pmyMac->d_mac[4], pmyMac->d_mac[5]);
	printf("MAC_S :%02X-%02X-%02X-%02X-%02X-%02X\n", pmyMac->s_mac[0], pmyMac->s_mac[1], pmyMac->s_mac[2], pmyMac->s_mac[3], pmyMac->s_mac[4], pmyMac->s_mac[5]);
	printf("pro   :%02X%02X\n", pmyMac->ver[0], pmyMac->ver[1]);

	REMOVEMAC_OFFSET(pack);
	ipHeadT* pmyIp = (ipHeadT*)pack;
	char strsip[16];
	char strdip[16];
	inet_ntop(AF_INET, pmyIp->sip, strsip, 16);
	inet_ntop(AF_INET, pmyIp->dip, strdip, 16);
	printf("sip : %s\n", strsip);
	printf("dip : %s\n", strdip);
*/

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "anaTool.h"

/*****************************************************************/

static int z_judgeIp_anaTool(uint64_t len, void *buf);
static proTypeE z_judgeTransport_anaTool(uint64_t len, void *buf);
static int z_judgeIcmpReq_anaTool(uint64_t len, void *buf);
static int z_judgeSYN_anaTool(uint64_t len, void *buf);

/*****************************************************************/

/*
*判断是否为IP协议
* ret：
 	0：是
 	-1：出错
 	1；否
*/
static int z_judgeIp_anaTool(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return -1;
	}
	char *pack = (char *)buf;

	if(len < Z_MACHEAD_LEN)
	{
		return -1;
	}

	macHeadT *pmyMac = (macHeadT *)pack;

	u_char c_tmpVer[2] = {pmyMac->ver[1], pmyMac->ver[0]};
	uint16_t i_tmpVer = 0;
	memcpy(&i_tmpVer, c_tmpVer, sizeof(uint16_t));

	if(Z_IP_TYPE == i_tmpVer )
	{
		return 0;
	}

	return 1;
}

/*
*判断 传输层 协议
* ret：
 	0：proTypeE 
 	-1：出错

*/
static proTypeE z_judgeTransport_anaTool(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return E_ERROR_TYPE;
	}
	char *pack = buf;

	int ret = z_judgeIp_anaTool(len, pack);
	if(ret == -1)
	{
		return E_ERROR_TYPE;
	}
	else if(ret == 1)
	{
		return E_ERROR_TYPE;
	}

	REMOVEMAC_OFFSET(pack);
	ipHeadT *pmyIp = (ipHeadT *)pack;

	if(Z_ICMP_TYPE == pmyIp->protocol)
	{
		return E_ICMP_TYPE;
	}
	else if(Z_TCP_TYPE == pmyIp->protocol)
	{
		return E_TCP_TYPE;
	}

	return E_UNKNOWN_TYPE;
}

/*
*判断是否为ICMP 的请求信号
* ret：
 	0：是
 	-1：出错
 	1；否
*/
static int z_judgeIcmpReq_anaTool(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return -1;
	}
	
	char* pack = buf;
	REMOVEMAC_OFFSET(pack);

	z_removeIpHead_anaTool(len, (void **)&pack );

	icmpHeadT* pmyIcmp = (icmpHeadT *)pack;
	if(Z_ICMPREQ_TYPE == pmyIcmp->tp_code)
	{
		return 0;
	}

	return 1;
}

/*
*判断是否为SYN
* ret：
 	0：是
 	-1：出错
 	1；否
*/
static int z_judgeSYN_anaTool(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return -1;
	}
	
	char* pack = buf;
	REMOVEMAC_OFFSET(pack);

	z_removeIpHead_anaTool(len, (void **)&pack );

	tcpHeadT* pmyTcp = (tcpHeadT *)pack;
	if(Z_TCPSYN_TYPE == pmyTcp->flag)
	{
		return 0;
	}

	return 1;
}
/*****************************************************************/


/*
* 判断包协议类型
* ret：
	返回协议类型
*/
proTypeE z_judgeType_anaTool(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return E_ERROR_TYPE;
	}

	proTypeE ret = z_judgeTransport_anaTool(len, buf);
	if(ret == E_ERROR_TYPE)
	{
		return E_ERROR_TYPE;
	}
	else if(ret == E_UNKNOWN_TYPE)
	{
		return E_UNKNOWN_TYPE;
	}
	else if(ret == E_ICMP_TYPE)
	{
		int tmp = 0;
		tmp = z_judgeIcmpReq_anaTool(len, buf);
		if(tmp == 1)
		{
			return E_ICMP_TYPE;
		}
		else if(tmp == -1)
		{
			return E_ERROR_TYPE;
		}
		else
		{
			return E_ICMPREQ_TYPE;
		}
	}
	else if(ret == E_TCP_TYPE)
	{
		int tmp = 0;
		tmp = z_judgeSYN_anaTool(len, buf);
		if(tmp == 1)
		{
			return E_TCP_TYPE;
		}
		else if(tmp == -1)
		{
			return E_ERROR_TYPE;
		}
		else
		{
			return E_TCPSYN_TYPE;
		}

	}

	return E_UNKNOWN_TYPE;
}

int z_removeIpHead_anaTool(uint64_t len, void **buf_ip)
{
	if(buf_ip == NULL)
	{
		return -1;
	}
	if(len < Z_IPHEAD_SMALL_LEN)
	{
		return -1;
	}

	ipHeadT* pmyIp = (ipHeadT*)(*buf_ip);
	uint8_t ipLen = pmyIp->ver_hdLen;
	ipLen = (ipLen & 0x0f) * 4;

	*buf_ip = (char *)(*buf_ip) + ipLen;

	return 0;
}

int z_getSMAC_anaTool(uint64_t buflen, void *buf, u_char* s_mac, uint8_t len)
{
	if(s_mac == NULL || buf == NULL)
	{
		return -1;
	}
	if(buflen < Z_MACHEAD_LEN)
	{
		return -1;
	}

	macHeadT* pmyMac = buf;

	memset(s_mac, 0, len);
	memcpy(s_mac, pmyMac->s_mac, len);

	return 0;
}
int z_getDMAC_anaTool(uint64_t buflen, void *buf, u_char* d_mac, uint8_t len)
{
	if(d_mac == NULL || buf == NULL)
	{
		return -1;
	}
	if(buflen < Z_MACHEAD_LEN)
	{
		return -1;
	}

	macHeadT* pmyMac = buf;
	memset(d_mac, 0, len);
	memcpy(d_mac, pmyMac->d_mac, len);

	return 0;
}