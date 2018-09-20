#ifndef _STATISTICS_H_H_
#define _STATISTICS_H_H_

#include <stdint.h>
#include <pthread.h>
#include "icmp.h"
#include "portScan.h"

/************************************************************/
#define Z_CLEAR_STATISTICS 10		//清空数据，默认30s

typedef struct _zPackBaseT{
	pthread_mutex_t mutex;
	uint64_t packNum;		//包数量
}zPackBaseT;

typedef struct _zStaticT{
	pthread_t  pth;		//定时处理线程
	zPackBaseT packBase;
	zIcmp icmp;
	zScan scan;
}zStaticT;

/************************************************************/

int z_init_statistics(void);
int z_static_statistics(uint64_t len, void *buf);
void z_free_statistics(void);

/************************************************************/

#endif