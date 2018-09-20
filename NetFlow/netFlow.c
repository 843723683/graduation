#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netFlow.h"
#include "../Analysis/statistics.h"

/*****************************************************************/

zNetFlowT *pNet_ex = NULL;

/*****************************************************************/
/*
*初始化结构体
*/
static zNetFlowT* z_initNetFlow_netFlow(void)
{
	zNetFlowT* pmyNet = NULL;
	pmyNet = malloc(sizeof(zNetFlowT));
	if(pmyNet == NULL)
	{
		return NULL;
	}
	memset(pmyNet, 0, sizeof(zNetFlowT));

	return pmyNet;
}

/*****************************************************************/

/*
* 所有需要的初始化
*ret: 0:成功
	  -1:失败
*/
int z_init_netFlow(int argc, char *argv[])
{
	pNet_ex = z_initNetFlow_netFlow();
	if(pNet_ex == NULL)
	{
		return -1;
	}

	pNet_ex->pDpdk = z_initEal_dpdk(argc, argv);
	if(pNet_ex->pDpdk == NULL)
	{
		return -1;
	}
	
	if(z_init_statistics() != 0)
	{
		return -1;
	}


	return 0;
}

/*
* 程序的总入口
*/
int z_start_netFlow(void)
{
	if (z_capture_dpdk(pNet_ex->pDpdk) != 0)
	{
		return -1;
	}	
	return 0;
}

/*
* 程序结束前的释放
*/
void z_free_netFlow(void)
{
	z_free_statistics();
	
	if(pNet_ex->pDpdk)
	{
		z_free_dpdk(pNet_ex->pDpdk);
	}
	if(pNet_ex)
	{
		free(pNet_ex);
	}
}