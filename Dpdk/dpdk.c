#include "dpdk.h"
#include "../Analysis/statistics.h"
#include <string.h>
#include <stdlib.h>

/*************************************************************************/
#define RX_RING_SIZE 128

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

typedef struct _zLcoreT{
	uint8_t nb_ports;		//端口数量
	uint8_t portid;			//端口id
	uint8_t lcore_id;		//绑核id
}zLcoreT;

/*************************************************************************/

static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool);
static int lcore_main(__attribute__((unused)) void *arg);

static zDpdkT* z_init_dpdk(void);
static int z_initPort_dpdk(unsigned nb_ports, struct rte_mempool *mbuf_pool);

/*************************************************************************/
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 0;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
*初始化结构体
*/
static zDpdkT* z_init_dpdk(void)
{
	zDpdkT* pmyDpdk = NULL;
	pmyDpdk = malloc(sizeof(zDpdkT));
	if(pmyDpdk == NULL)
	{
		return NULL;
	}
	memset(pmyDpdk, 0, sizeof(zDpdkT));

	return pmyDpdk;
}

/*
* 初始化 端口。
*/
static int z_initPort_dpdk(unsigned nb_ports, struct rte_mempool *mbuf_pool)
{
	uint8_t i = 0;
	if(mbuf_pool == NULL)
	{
		return -1;
	}
	/* Initialize all ports. */
	for (i = 0; i < nb_ports; i++)
	{
		if (port_init(i, mbuf_pool) != 0)
		{
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", i);	
			return -1;
		}
	}
	return 0;
}

/*static int z_test(uint16_t num)
{
	static uint16_t sum = 0;
	sum += num;
	if(sum % 10 == 0)
	{
		printf("sum = %u\n", sum);
		return 0;
	}
	return -1;
}*/

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
lcore_main(__attribute__((unused)) void *arg)
{
	if(arg == NULL)
	{
		return -1;
	}
	zLcoreT *pmyLcore = (zLcoreT *)arg;

	const uint8_t nb_ports = pmyLcore->nb_ports;
	uint8_t port = pmyLcore->portid;
	uint8_t lcoreid = pmyLcore->lcore_id;

	printf("\nnb_ports = %u, portid = %u, lcoreid = %u\n", nb_ports, port, lcoreid);
	printf("Core %u forwarding packets. [Ctrl+C to quit]\n", lcoreid);

	/* Run until the application is quit or killed. */
	uint16_t buf = 0;
	for (;;) 
	{
		/* Get burst of RX packets, from first port of pair. */
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
		{
			continue;
		}

		for(buf = 0; buf < nb_rx; buf++)
		{
			z_static_statistics( rte_pktmbuf_data_len(bufs[buf]), rte_pktmbuf_mtod(bufs[buf], void *) );
		}

		/* Free any unsent packets. */
		for (buf = 0; buf < nb_rx; buf++)
		{
			rte_pktmbuf_free(bufs[buf]);
		}

		//test
	//	if(z_test(nb_rx) == 0)
		{
			// printf("lcoreid = %u stop\n", lcoreid);
			// break;
		}
	}
	return 0;
}

/**************************************************************************************/
/*
* 初始化 rte_eal_init、内存池。
*/
zDpdkT* z_initEal_dpdk(int argc, char *argv[])
{

	zDpdkT* pmyDpdk = z_init_dpdk();
	if(pmyDpdk == NULL)
	{
		return NULL;
	}

	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
		z_free_dpdk(pmyDpdk);
		return NULL;
	}

	// argc -= ret;
	// argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	pmyDpdk->pInit.nb_ports = nb_ports;

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
	MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
	{
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
		z_free_dpdk(pmyDpdk);
		return NULL;
	}
	pmyDpdk->pInit.mbuf_pool = mbuf_pool;	

	if(z_initPort_dpdk(pmyDpdk->pInit.nb_ports, pmyDpdk->pInit.mbuf_pool) != 0)
	{
		z_free_dpdk(pmyDpdk);
		return NULL;
	}

	return pmyDpdk;
}


/*
*  绑核进行抓包
*/
int z_capture_dpdk(zDpdkT* paDpdk)
{
	if(paDpdk == NULL)
	{
		return -1;
	}
	zDpdkT* pmyDpdk = paDpdk;
	unsigned nb_ports = pmyDpdk->pInit.nb_ports;

	unsigned portid = 0;
	unsigned lcore_id;
	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if(portid < nb_ports)
		{
			zLcoreT myLcore = {nb_ports, portid, lcore_id};
			rte_eal_remote_launch(lcore_main, &myLcore, lcore_id);
			++portid;
		}
		else
		{
			break;
		}
	}

	rte_eal_mp_wait_lcore();
	return 0;
}

/*
*  dpdk释放函数
*/
void z_free_dpdk(zDpdkT* paDpdk)
{
	if(paDpdk)
	{
		free(paDpdk);
	}
}

/**************************************************************************************/