#ifndef _DPDK_H_H_
#define _DPDK_H_H_

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

/*****************************************************************/

typedef struct _zDpdkInitT{
	struct rte_mempool *mbuf_pool;		//内存池
	unsigned nb_ports;					//端口数量
}zDpdkInitT;

typedef struct _zDpdkT{
	zDpdkInitT pInit;
}zDpdkT;

/*****************************************************************/

zDpdkT* z_initEal_dpdk(int argc, char *argv[]);
int z_capture_dpdk(zDpdkT* paDpdk);
void z_free_dpdk(zDpdkT* paDpdk);

/*****************************************************************/

#endif