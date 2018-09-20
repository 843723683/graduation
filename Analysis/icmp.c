#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>

#include "icmp.h"
#include "anaTool.h"

/******************************************************************/

static void key_free (void* data);
static void value_free (void* data);

/******************************************************************/
static void key_free (void* data)
{
	if(data != NULL)
	{
		free(data);
	}
}
static void value_free (void* data)
{
	if(data != NULL)
	{
		free(data);
	}
}
/******************************************************************/

int z_init_icmp(zIcmp *paIcmp)
{
	if(paIcmp == NULL)
	{
		return -1;
	}
	zIcmp* pmyIcmp = paIcmp;

	if(pthread_mutex_init(&pmyIcmp->mutex, NULL) != 0)
	{
		return -1;
	}
	pmyIcmp->pHash = g_hash_table_new_full ( g_str_hash, g_str_equal, key_free, value_free);
	if(pmyIcmp->pHash == NULL)
	{
		return -1;
	}

	return 0;
}

int z_analysis_icmp(zIcmp *paIcmp, int len, void* buf)
{
	if(paIcmp == NULL || paIcmp->pHash == NULL || buf == NULL)
	{
		return -1;
	}
	zIcmp *pmyIcmp = paIcmp;
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
	uint64_t *o_value = NULL;
	char *key = NULL;
	//由sip + smac组成
	key = malloc(6 + 4 + 1);
	if(key == NULL)
	{
		return -1;
	}
	memset(key , 0, 6 + 4 + 1);	
	memcpy(key, s_mac, 6);
	memcpy(key + 6, pmyIp->sip, 4);

	pthread_mutex_lock(&pmyIcmp->mutex);

	if(g_hash_table_lookup_extended (pmyIcmp->pHash, key, NULL, (void **)&o_value) == TRUE)
	{
		free(key);
		//存在
		*o_value = *o_value + 1;
	}
	else
	{
		//不存在
		uint64_t *value = NULL;
		value = malloc(sizeof(uint64_t));
		if(value == NULL)
		{
			return -1;
			pthread_mutex_unlock(&pmyIcmp->mutex);
		}
		*value = 1;

		if(g_hash_table_insert (pmyIcmp->pHash, key, (void *)value) != TRUE)
		{
			pthread_mutex_unlock(&pmyIcmp->mutex);
			return -1;
		}
	}

	pthread_mutex_unlock(&pmyIcmp->mutex);

	return 0;
}

static gboolean hashForeach_callback(gpointer key, gpointer value, __attribute__((unused))gpointer user_data)
{
	if(key == NULL || value == NULL)
	{
		return FALSE;
	}
	char* mac_ip = key;
	uint64_t* pSum = (uint64_t*)value;
	
	if(*pSum > Z_ICMPREQ_LIMIT)
	{
		u_char s_mac[6] = {0};
		u_char s_ip[4] = {0};
		memcpy(s_mac, mac_ip, 6);
		memcpy(s_ip, mac_ip + 6, 4);

		char strsip[16];
		inet_ntop(AF_INET, s_ip, strsip, 16);
		
		printf("\t ______________________________________\n");
		printf("\t|                                      |\n");
		printf("\t|       正在受到 Ping Flood 攻击！     |\n");
		printf("\t|*攻击次数：%lu                         |\n", *pSum);
		printf("\t|*攻击者的 MAC 地址 :%02X-%02X-%02X-%02X-%02X-%02X |\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
		printf("\t|*攻击者的 Ip  地址 :%s     |\n", strsip);
		printf("\t|______________________________________|\n");

	}

	return TRUE;
}

int z_clearHash_icmp(zIcmp *paIcmp)
{
	if(paIcmp == NULL)
	{
		return -1;
	}
	zIcmp* pmyIcmp = paIcmp;

	pthread_mutex_lock(&pmyIcmp->mutex);

	g_hash_table_foreach_remove (pmyIcmp->pHash, hashForeach_callback, NULL);
//	printf("end size = %u\n", g_hash_table_foreach_remove (pmyIcmp->pHash, hashForeach_callback, NULL));

	pthread_mutex_unlock(&pmyIcmp->mutex);


	return 0;
}

void z_free_icmp(zIcmp *paIcmp)
{
	if(paIcmp == NULL)
	{
		return ;
	}
	zIcmp* pmyIcmp = paIcmp;

	pthread_mutex_destroy(&pmyIcmp->mutex);
	g_hash_table_destroy (pmyIcmp->pHash);

}