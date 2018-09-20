#ifndef _ZICMP_H_H_
#define _ZICMP_H_H_

#include <glib.h>
#include <pthread.h>

/************************************************************/

#define Z_ICMPREQ_LIMIT (5)

typedef struct _zIcmp{
	pthread_mutex_t mutex;
	GHashTable* pHash;		//key = ip,value = icmpÊýÁ¿
}zIcmp;

/************************************************************/

int z_init_icmp(zIcmp *paIcmp);
int z_analysis_icmp(zIcmp *paIcmp, int len, void* buf);
int z_clearHash_icmp(zIcmp *paIcmp);
void z_free_icmp(zIcmp *paIcmp);

/************************************************************/

#endif