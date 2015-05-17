/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_random.h>
#include <rte_log.h>
#include <rte_pci.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_mbuf.h>
#include <rte_devargs.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "fdb.h"
#include "arp.h"
#include "runtime.h"

static int
ip_input(struct lcore_env *env, struct rte_mbuf* buf)
{
    return 0;
}

#define mmalloc(x) rte_malloc("l2sw", (x), 0)
#define mfree(x) rte_free((x))

#define FDB_SIZE 1 << 20

#define RTE_LOGTYPE_MARIO RTE_LOGTYPE_USER1

#define MBUF_DATA_SIZE (2048 + RTE_PKTMBUF_HEADROOM)
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define NB_MBUF   8192
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_RX_QUEUE_PER_LCORE 16

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 256
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/*
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
*/
#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  };

static const struct rte_eth_conf port_conf = {
	.rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
  .rx_adv_conf = {
    .rss_conf = {
.rss_key=hash_key,
   .rss_hf = ETH_RSS_IP,
   },
       },
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct l2sw_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;

/* list of per-port statistics */
struct l2sw_port_statistics port_statistics[RTE_MAX_ETHPORTS];
/* ethernet addresses of ports */
static struct ether_addr l2sw_ports_eth_addr[RTE_MAX_ETHPORTS];
struct rte_mempool *l2sw_pktmbuf_pool = NULL;
static unsigned int l2sw_rx_queue_per_lcore = RTE_MAX_ETHPORTS;

#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* default period is 10 seconds */
static int64_t timer_period = 5 * TIMER_MILLISECOND * 1000;

/* Print out statistics on packets dropped */
static void
print_stats(struct lcore_env *env)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	//const char clr[] = { 27, '[', '2', 'J', '\0' };
	//const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	//printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

  uint8_t n = env->n_port;
	for (uint8_t port_id = 0; port_id < n; port_id++) {
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   port_id,
			   port_statistics[port_id].tx,
			   port_statistics[port_id].rx,
			   port_statistics[port_id].dropped);

		total_packets_dropped += port_statistics[port_id].dropped;
		total_packets_tx += port_statistics[port_id].tx;
		total_packets_rx += port_statistics[port_id].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static void
l2sw_send_burst(struct lcore_env* env, uint8_t dst_port, unsigned n)
{
  struct rte_mbuf **m_table;
  unsigned ret;
  unsigned queue_id;
  
  m_table = (struct rte_mbuf**)env->tx_mbufs[dst_port].m_table;
  
  ret = rte_eth_tx_burst(dst_port, (uint16_t) env->lcore_id, m_table, n);
  port_statistics[dst_port].tx += ret;
  if (unlikely(ret < n)) {
    port_statistics[dst_port].dropped += (n - ret);
    do {
      rte_pktmbuf_free(m_table[ret]);
    } while(++ret < n);
  }
  return ;
}

static void
l2sw_sending_packet(struct lcore_env *env, struct rte_mbuf *buf,
                    uint8_t src_port , uint8_t dst_port)
{
  unsigned len = env->tx_mbufs[dst_port].len;
  env->tx_mbufs[dst_port].m_table[len++] = buf;
  
  if (unlikely(len == MAX_PKT_BURST)) {
    l2sw_send_burst(env, dst_port, len);
    len = 0;
  }
  env->tx_mbufs[dst_port].len = len;
  return ;
}

static void
l2sw_flooding(struct lcore_env *env, struct rte_mbuf *buf,
              uint8_t src_port)
{
  uint8_t n = env->n_port;
  uint8_t i = 0;
  
  for (uint8_t port_id = 0; port_id < n; port_id++) {
    struct rte_mbuf *buff;
    if (port_id == src_port) continue;
    if (++i != n-1)
      buff = rte_pktmbuf_clone(buf, l2sw_pktmbuf_pool);
    else
      buff = buf;
    l2sw_sending_packet(env, buff, src_port, port_id);
  }
}

static void
ether_switching(struct lcore_env *env, struct rte_mbuf* buf,
               uint8_t src_port)
{
  struct fdb_table *fdb = env->fdb;
  struct fdb_entry *dst_entry;
  struct ether_hdr *eth;
  uint8_t dst_port;

	eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  dst_entry = lookup_fdb_entry(fdb, &eth->d_addr);
  add_fdb_entry(fdb, &eth->s_addr, src_port);;
  if (dst_entry == NULL) {
    l2sw_flooding(env, buf, src_port);
  } else {
    // XXX
    // must check expire & if so, flooding
    dst_port = dst_entry->port;
    l2sw_sending_packet(env, buf, src_port, dst_port);
  }
}

static void
ether_input(struct lcore_env *env, struct rte_mbuf** bufs,
            unsigned n_rx, uint8_t src_port)
{
  for(uint32_t j = 0; j < n_rx; j++) {
    int res = 0;
    struct rte_mbuf* pkt = bufs[j];
    rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
    
    struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    RTE_LOG(INFO, MARIO, "%s\n\tl2_len: %d\n\tl3_len:%d\n\tl4_len:%d\n",
            __func__, pkt->l2_len, pkt->l3_len, pkt->l4_len);
    pkt->l2_len = ETHER_HDR_LEN;
    switch (eth->ether_type) {
      case ETHER_TYPE_ARP: {
        res = arp_input(env, pkt);
        break;
      }
      case ETHER_TYPE_IPv4: {
        res = ip_input(env, pkt);
        break;
      }
      case ETHER_TYPE_IPv6: {
        ;
        break;
      }
    }

    /**
     * If ret is 0, need to l2-switching.
     * Or no need any more processing.
     */
    if (res) {
      // consumed
      continue;
    }

    ether_switching(env, pkt, src_port);    
  }
}

static void
l2sw_main_process(struct lcore_env *env)
{
  struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
  uint8_t n_ports = rte_eth_dev_count();
  unsigned lcore_id = rte_lcore_id();
  uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
  const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S 
                             * BURST_TX_DRAIN_US;
  
  RTE_LOG(INFO, MARIO, "[%u] Starting main processing.\n", lcore_id);
  
	prev_tsc = 0;
	timer_tsc = 0;
  while(1) {
    cur_tsc = rte_rdtsc();
    
    diff_tsc = cur_tsc - prev_tsc;
    if (unlikely(diff_tsc > drain_tsc)) {
      for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
				if (env->tx_mbufs[port_id].len == 0)
					continue;
				l2sw_send_burst(env, port_id, env->tx_mbufs[port_id].len);
				env->tx_mbufs[port_id].len = 0;
      }

			/* if timer is enabled */
			if (timer_period > 0) {
				/* advance the timer */
				timer_tsc += diff_tsc;
				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats(env);
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}
      prev_tsc = cur_tsc;
    }

    /* RX */
    for (uint8_t port_id = 0; port_id < n_ports; port_id++) {
      unsigned n_rx = rte_eth_rx_burst(port_id, lcore_id,
                                       pkt_burst, MAX_PKT_BURST);
      if (n_rx != 0)
        RTE_LOG(INFO, MARIO, "[%u-%u] %u packet(s) came.\n",
                lcore_id, port_id,  n_rx);

      __sync_fetch_and_add(&port_statistics[port_id].rx, n_rx);

      ether_input(env, pkt_burst, n_rx, port_id);
    }
  }
  return ;
}

static int
l2sw_launch_one_lcore(void *env)
{
	RTE_LOG(INFO, MARIO, "[%u]processing launch\n", rte_lcore_id());
  uint8_t lcore_id = rte_lcore_id();

  l2sw_main_process(((struct lcore_env**) env)[lcore_id]);
  
	return 0;
}

static void
l2sw_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n",
	       prgname);
}

static unsigned int
l2sw_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return (unsigned int) n;
}

static int
l2sw_parse_args(int argc, char **argv)
{
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {
    {NULL, 0, 0, 0}
  };

  argvopt = argv;

  while((opt = getopt_long(argc, argvopt, "q:", lgopts, &option_index))
        != EOF){
    switch (opt) {
      case 'q':
        l2sw_rx_queue_per_lcore = l2sw_parse_nqueue(optarg);
        if (l2sw_rx_queue_per_lcore == 0) {
          RTE_LOG(ERR, MARIO, "Invalid queue number\n");
          return -1;
        }
        break;
      default:
        l2sw_usage(prgname);
        return -1;
    }
  }
         
  if (optind >= 0)
    argv[optind-1] = prgname;

  ret = optind - 1;
  optind = 0; 
  return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
main(int argc, char **argv)
{
  //struct lcore_queue_conf *qconf = NULL;
  //struct rte_eth_dev_info dev_info;
  struct lcore_env** envs;
  int ret;
  uint8_t n_ports;
  unsigned lcore_count;
  struct fdb_table *fdb;
  
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  ret = l2sw_parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid MARIO arguments\n");

  lcore_count = rte_lcore_count();
  n_ports = rte_eth_dev_count();
  RTE_LOG(INFO, MARIO, "Find %u logical cores\n" , lcore_count);

  l2sw_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 32, 0,
                                              MBUF_DATA_SIZE, 
                                              rte_socket_id());
  if (l2sw_pktmbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

  n_ports = rte_eth_dev_count();
  if (n_ports == 0) 
    rte_exit(EXIT_FAILURE, "No Ethernet ports - byte\n");
  RTE_LOG(INFO, MARIO, "Find %u ethernet ports\n", n_ports);

  if (n_ports > RTE_MAX_ETHPORTS)
    n_ports = RTE_MAX_ETHPORTS;

	/* Each logical core is assigned a dedicated TX queue on each port. */
  /*
  for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
    rte_eth_dev_info_get(port_id, &dev_info);
  }
  */
	/* Initialize the port/queue configuration of each logical core */
  /*
  for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
    ;
  }
  */

  /* Initialize lcore_env */
  envs = (struct lcore_env**) mmalloc(sizeof(struct lcore_env*));
  if (envs == NULL) 
    rte_exit(EXIT_FAILURE, "Cannot allocate memory for core envs\n");

  fdb = create_fdb_table(FDB_SIZE);
  if (fdb == NULL) 
    rte_exit(EXIT_FAILURE, "Fail to create fdb\n");
  for (uint8_t lcore_id = 0; lcore_id < lcore_count; lcore_id++) {
    struct lcore_env* env;
    env = (struct lcore_env*) mmalloc(sizeof(struct lcore_env) +
                                      sizeof(struct mbuf_table) *n_ports);
    if (env == NULL) 
      rte_exit(EXIT_FAILURE, 
               "Cannot allocate memory for %u core env\n", lcore_id);
    env->n_port = n_ports;
    env->lcore_id = lcore_id;
    env->fdb = fdb;
    memset(env->tx_mbufs, 0, sizeof(struct mbuf_table) * n_ports);
    envs[lcore_id] = env;
  }

	/* Initialise each port */
  for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
    RTE_LOG(INFO, MARIO, "Initializing port %u...", port_id);
    fflush(stdout);
    ret = rte_eth_dev_configure(port_id, lcore_count, lcore_count, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
               ret, (unsigned)port_id);
    RTE_LOG(INFO, MARIO, "done\n");
		rte_eth_macaddr_get(port_id, &l2sw_ports_eth_addr[port_id]);

		/* init one RX queue */
    for (uint8_t core_id = 0; core_id < lcore_count; core_id++) {
      ret = rte_eth_rx_queue_setup(port_id, core_id, nb_rxd,
                                   rte_eth_dev_socket_id(port_id),
                                   NULL,
                                   l2sw_pktmbuf_pool);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, 
                 "rte_eth_rx_queue_setup:err=%d, port=%u queue=%u\n",
                 ret, (unsigned) port_id, (unsigned) core_id);
    }

		/* init one TX queue */
    for (uint8_t core_id = 0; core_id < lcore_count; core_id++) {
      ret = rte_eth_tx_queue_setup(port_id, core_id, nb_txd,
                                   rte_eth_dev_socket_id(port_id), NULL);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, 
                 "rte_eth_tx_queue_setup:err=%d, port=%u queue=%u\n",
                 ret, (unsigned) port_id, (unsigned) core_id);
    }

		/* Start device */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
               ret, (unsigned) port_id);

    rte_eth_promiscuous_enable(port_id);

    RTE_LOG(INFO, MARIO,
            "Port %u, MAC address %02x:%02x:%02x:%02x:%02x:%02x\n\n",
            port_id,
            l2sw_ports_eth_addr[port_id].addr_bytes[0],
            l2sw_ports_eth_addr[port_id].addr_bytes[1],
            l2sw_ports_eth_addr[port_id].addr_bytes[2],
            l2sw_ports_eth_addr[port_id].addr_bytes[3],
            l2sw_ports_eth_addr[port_id].addr_bytes[4],
            l2sw_ports_eth_addr[port_id].addr_bytes[5]);
            
    memset(&port_statistics, 0, sizeof(port_statistics));
  }

	check_all_ports_link_status(n_ports);

	/* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(l2sw_launch_one_lcore, envs, CALL_MASTER);
  {
    uint8_t lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
      if (rte_eal_wait_lcore(lcore_id) < 0)
        return -1;
    }
  }

  return 0;
}

