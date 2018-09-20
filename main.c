#include <stdio.h>
#include "./NetFlow/netFlow.h"

int main(int argc, char *argv[])
{
	if(z_init_netFlow(argc, argv) == 0)
	{
		if(z_start_netFlow() != 0)
		{
			printf("z_start_netFlow failed \n");
		}
	}
	else
	{
		printf("z_init_netFlow failed \n");
	}

	z_free_netFlow();

	return 0;
}