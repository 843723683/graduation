#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>

#include "portScan.h"
#include "anaTool.h"

/******************************************************************/

static void free_gqueue (void * data);
static void key_free_out (void* data);
static void value_free_out (void* data);

/******************************************************************/
static gint compare_glist (gconstpointer a, gconstpointer b)
{
	const uint16_t *pa = (const uint16_t *)a;
	const uint16_t *pb = (const uint16_t *)b;

	if(*pa == *pb)
	{
		return 0;
	}
	else if(*pa > *pb)
	{
		return 1;
	}
	else
	{
		return -1;
	}
}
static void free_gqueue (void* data)
{
	if(data)
	{
		free(data);
	}
}

static void key_free_out (void* data)
{
	if(data != NULL)
	{
		free(data);
	}
}
static void value_free_out (void* data)
{
	if(data != NULL)
	{
		GQueue *pQue = (GQueue *)data;

		uint16_t count = g_queue_get_length (pQue);

		uint16_t i = 0;
		char *ptmp = NULL;
		for(i = 0; i < count; ++i)
		{
			ptmp = g_queue_pop_head (pQue);
			free_gqueue( ptmp );
		}

		g_queue_free (pQue);
	}
}

/******************************************************************/

int z_init_portScan(zScan *paScan)
{
	if(paScan == NULL)
	{
		return -1;
	}
	zScan* pmyScan = paScan;

	if(pthread_mutex_init(&pmyScan->mutex, NULL) != 0)
	{
		return -1;
	}
	pmyScan->pHash = g_hash_table_new_full ( g_str_hash, g_str_equal, key_free_out, value_free_out);
	if(pmyScan->pHash == NULL)
	{
		return -1;
	}

	return 0;
}
int z_analysis_portScan(zScan *paScan, int len, void* buf)
{
	if(paScan == NULL || paScan->pHash == NULL || buf == NULL)
	{
		return -1;
	}
	zScan* pmyScan = paScan;
	char* pack = buf;

	//解析MAC头
	u_char s_mac[6];
	u_char d_mac[6];
	z_getSMAC_anaTool(len, buf, s_mac, 6);
	z_getDMAC_anaTool(len, buf, d_mac, 6);

	//解析IP头
	REMOVEMAC_OFFSET(pack);
	ipHeadT* pmyIp = (ipHeadT*)pack;

	//ICMP 数据统计
	GQueue *o_value = NULL;
	char *key_out = NULL;
	//key_out 由sip + smac组成
	key_out = malloc(6 + 4 + 1);
	if(key_out == NULL)
	{
		return -1;
	}
	memset(key_out , 0, 6 + 4 + 1);	
	memcpy(key_out, s_mac, 6);
	memcpy(key_out + 6, pmyIp->sip, 4);

	//去掉IP头
	z_removeIpHead_anaTool(len, (void **)&pack );
	//获取dport
	tcpHeadT* pmyTcp = (tcpHeadT *)pack;	
	uint16_t dport = (pmyTcp->dport[0]<<8 ) + pmyTcp->dport[1];
	uint16_t *pdport = malloc(sizeof(uint16_t));
	memcpy(pdport, &dport, sizeof(uint16_t));	

	pthread_mutex_lock(&pmyScan->mutex);

	if(g_hash_table_lookup_extended (pmyScan->pHash, key_out, NULL, (void **)&o_value) == TRUE)
	{
		free(key_out);
		//存在
		if(g_queue_find_custom (o_value, (gconstpointer) pdport, compare_glist) == NULL)
		{
			g_queue_push_head (o_value, (gpointer) pdport);
		}
		else
		{
			free(pdport);
		}
	}
	else   //不存在
	{
		//插入队列
		GQueue * pQue = g_queue_new ();
		g_queue_init (pQue);
		g_queue_push_head (pQue, (gpointer) pdport);

		if(g_hash_table_insert (pmyScan->pHash, key_out, (void *)pQue) != TRUE)
		{
			pthread_mutex_unlock(&pmyScan->mutex);
			return -1;
		}
	}

	pthread_mutex_unlock(&pmyScan->mutex);

	return 0;
}

static gboolean hashForeach_callback(gpointer key, gpointer value, __attribute__((unused))gpointer user_data)
{
	if(key == NULL || value == NULL)
	{
		return FALSE;
	}
	char* mac_ip = key;
	GQueue* pQue = (GQueue*)value;
	
	// unsigned int num = g_list_length (plist);
	unsigned int num = g_queue_get_length (pQue);;
	if(num > Z_TCPPORTSCAN_LIMIT)
	{
		u_char s_mac[6] = {0};
		u_char s_ip[4] = {0};
		memcpy(s_mac, mac_ip, 6);
		memcpy(s_ip, mac_ip + 6, 4);

		char strsip[16];
		inet_ntop(AF_INET, s_ip, strsip, 16);
		
		printf("\t****************************************\n");
		printf("\t*         正在受到 SYN 端口扫描！      *\n");
		printf("\t*-扫描端口数：%u                     *\n", num);
		printf("\t*-攻击者的 MAC 地址 :%02X-%02X-%02X-%02X-%02X-%02X *\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
		printf("\t*-攻击者的 Ip  地址 :%s     *\n", strsip);
		printf("\t****************************************\n");

	}

	return TRUE;
}

int z_clearHash_portScan(zScan *paScan)
{
	if(paScan == NULL)
	{
		return -1;
	}
	zScan* pmyScan = paScan;

	pthread_mutex_lock(&pmyScan->mutex);

	g_hash_table_foreach_remove (pmyScan->pHash, hashForeach_callback, NULL);
	// printf("end size = %u\n", g_hash_table_foreach_remove (pmyScan->pHash, hashForeach_callback, NULL));
	pthread_mutex_unlock(&pmyScan->mutex);

	return 0;
}

void z_free_portScan(zScan *paScan)
{
	if(paScan == NULL)
	{
		return ;
	}
	zScan* pmyScan = paScan;

	pthread_mutex_destroy(&pmyScan->mutex);
	g_hash_table_destroy (pmyScan->pHash);
}