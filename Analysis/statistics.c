#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "statistics.h"
#include "anaTool.h"


zStaticT myStatic;

/************************************************************/

// static void print_FlowSize(uint64_t packNum);

static void* clear_callback(void * arg);
static int z_initBase_statistics(zPackBaseT *paBase);
static int z_AnalysisBase_statistics(zPackBaseT *paBase);
static int z_clearBase_staticstics(zPackBaseT *paBase);
static int z_freeBase_statistics(zPackBaseT *paBase);

/************************************************************/

/*static void print_FlowSize(uint64_t packNum)
{
	uint64_t i = 0;

	for( i = 0; i < packNum/2; ++i)
	{
		printf("=");
	}
	printf(">%lu\n", packNum);
}*/
static void printf_time(void)
{
	struct tm *t;
	time_t tt;
	time(&tt);
	t = localtime(&tt);
	printf("\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	printf("%4d年%02d月%02d日 %02d:%02d:%02d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);	
}
static void* clear_callback(__attribute__((unused))void * arg)
{
	for(;;)
	{
		sleep(Z_CLEAR_STATISTICS);

		printf_time();

		z_clearBase_staticstics(&myStatic.packBase);
		z_clearHash_icmp(&myStatic.icmp);
		z_clearHash_portScan(&myStatic.scan);
	}
	return NULL;
}

static int z_initBase_statistics(zPackBaseT *paBase)
{
	if(paBase == NULL)
	{
		return -1;
	}
	zPackBaseT* pmyBase = paBase;

	if(pthread_mutex_init(&pmyBase->mutex, NULL) != 0)
	{
		return -1;
	}

	return 0;
}

static int z_AnalysisBase_statistics(zPackBaseT *paBase)
{
	if(paBase == NULL)
	{
		return -1;
	}
	zPackBaseT *pmyBase = paBase;

	pthread_mutex_lock(&pmyBase->mutex);

	pmyBase->packNum++;

	pthread_mutex_unlock(&pmyBase->mutex);

	return 0;
}
static int z_clearBase_staticstics(zPackBaseT *paBase)
{
	if(paBase == NULL)
	{
		return -1;
	}
	zPackBaseT *pmyBase = paBase;

	pthread_mutex_lock(&pmyBase->mutex);

	// print_FlowSize(pmyBase->packNum);
	myStatic.packBase.packNum = 0;

	pthread_mutex_unlock(&pmyBase->mutex);	

	return 0;
}
static int z_freeBase_statistics(zPackBaseT *paBase)
{
	if(paBase == NULL)
	{
		return -1;
	}
	zPackBaseT *pmyBase = paBase;

	pthread_mutex_destroy(&pmyBase->mutex);
	return 0;
}
/************************************************************/

int z_init_statistics(void)
{
	memset(&myStatic, 0, sizeof(zStaticT));
	pthread_create(&myStatic.pth, NULL, clear_callback, NULL);

	if(z_initBase_statistics(&myStatic.packBase) != 0)
	{
		return -1;
	}
	if(z_init_icmp(&myStatic.icmp) != 0)
	{
		return -1;
	}
	if(z_init_portScan(&myStatic.scan) != 0)
	{
		return -1;
	}

	return 0;
}

int z_static_statistics(uint64_t len, void *buf)
{
	if(buf == NULL)
	{
		return -1;
	}

	if(z_AnalysisBase_statistics(&myStatic.packBase) != 0)
	{
		return -1;
	}

	proTypeE ret = z_judgeType_anaTool(len, buf);
	if(ret == E_ICMPREQ_TYPE)
	{
		//识别和处理 PING 攻击
		if(z_analysis_icmp(&myStatic.icmp, len, buf) != 0)
		{
			return -1;
		}
	}
	else if(ret == E_TCPSYN_TYPE)
	{
		//识别和处理 端口扫描 
		if(z_analysis_portScan(&myStatic.scan, len, buf) != 0)
		{
			return -1;
		}
	}

	return 0;
}

void z_free_statistics(void)
{
	z_freeBase_statistics(&myStatic.packBase);
	z_free_icmp(&myStatic.icmp);
	z_free_portScan(&myStatic.scan);
}