#ifndef _NETFLOW_H_H_
#define _NETFLOW_H_H_

#include "../Dpdk/dpdk.h"

/*****************************************************************/
typedef struct _zNetFlowT{
	zDpdkT* pDpdk;
}zNetFlowT;

/*****************************************************************/

int z_init_netFlow(int argc, char *argv[]);
int z_start_netFlow(void);
void z_free_netFlow(void);

/*****************************************************************/

#endif