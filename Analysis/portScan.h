#ifndef _PORTSCAN_H_H_
#define _PORTSCAN_H_H_

#include <glib.h>
#include <pthread.h>

/************************************************************/
#define Z_TCPPORTSCAN_LIMIT (100)

typedef struct _zScan{
	pthread_mutex_t mutex;
	GHashTable* pHash;
}zScan;

/************************************************************/

int z_init_portScan(zScan *paScan);
int z_analysis_portScan(zScan *paScan, int len, void* buf);
int z_clearHash_portScan(zScan *paScan);
void z_free_portScan(zScan *paScan);

/************************************************************/

#endif