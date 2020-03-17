/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_vxlan.h>
#include <rte_hash.h>

#define false               0
#define true                1

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  1024

/* Number of TX ring descriptors */
#define NB_TXD                  1024

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32

#define AC_MAC_FWD_ENTRY_NUM    (128*1024)
#define AC_CONF_CHECK_CYCLE             (1000*1000*1000)        // 2GHz, 0.5s

#define AC_KNI_FIFO_SIZE          1024

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
        /* number of pkts received from NIC, and sent to KNI */
        uint64_t rx_packets;

        /* number of pkts received from NIC, but failed to send to KNI */
        uint64_t rx_dropped;

        /* number of pkts received from KNI, and sent to NIC */
        uint64_t tx_packets;

        /* number of pkts received from KNI, but failed to send to NIC */
        uint64_t tx_dropped;
};

enum ac_lcore_type {
        AC_LCORE_TYPE_NONE,
        AC_LCORE_TYPE_TUNNEL,
        AC_LCORE_TYPE_KNI                               // line pkts xmit to kernel
};

struct ac_fwd_entry {
        struct rte_ether_addr   device_smac;
        struct rte_ether_addr   client_smac;
        rte_be32_t                              client_sip;
        rte_be16_t                              client_sudpp;
        uint64_t                                touch_cycle;
        uint64_t                                check_cycle;
        uint64_t                                rx_pkts;
        uint64_t                                tx_pkts;
};

/*
 * Structure of fwd parameters
 */
struct ac_lcore_conf {
        uint16_t lcore_id;
        unsigned queue_id;
        uint64_t ageing_cycle;
        unsigned ageing_start_index;
        unsigned ageing_end_index;
        uint64_t tx_out_drop;
        enum ac_lcore_type type;
} __rte_cache_aligned;

#define AC_MAX_LCORE            64

struct ac_tunnel_header {
        struct rte_ether_hdr eth_hdr;
        struct rte_ipv4_hdr ipv4_hdr;
        struct rte_udp_hdr udp_hdr;
};
#define AC_TUNNEL_HEAD_SIZE             (sizeof(struct ac_tunnel_header))


// from ac
struct ac_config {
        struct rte_ether_addr ac_mac;
        rte_be32_t                        ac_sip;
        rte_be16_t                        ac_sport;
        unsigned                          ac_mtu;
        uint64_t                          lcore; // lcore bitmap
        unsigned                          nb_lcore;
        struct ac_fwd_entry **hash_map;
        struct rte_hash*          hash_handle;
        struct ac_lcore_conf  lcore_conf[AC_MAX_LCORE];
        struct ac_tunnel_header header_templete;

        /* kni related */
        struct rte_kni*                         kni;
        struct kni_interface_stats      kni_stats;
        /* kernel(signel producer) pkts --> line(multi consumer) */
        struct rte_ring*                        kni_spring;
        /* line(multi producer) pkts --> kernel(signel consumer) */
        struct rte_ring*                        kni_mpring;
} g_ac_conf;




/* Options for configuring ethernet port */
static struct rte_eth_conf kni_port_conf = {
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
                .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM,
        },
};

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 1;
/* Monitor link status continually. off by default. */
static int monitor_links;

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);

/* Print out statistics on packets handled */
static void
print_stats(void)
{

}

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
        struct kni_interface_stats *kni_stats = &g_ac_conf.kni_stats;

        /* When we receive a USR1 signal, print stats */
        if (signum == SIGUSR1) {
                print_stats();
        }

        /* When we receive a USR2 signal, reset stats */
        if (signum == SIGUSR2) {
                memset(kni_stats, 0, sizeof(*kni_stats));
                printf("\n** Statistics have been reset **\n");
                return;
        }

        /*
         * When we receive a RTMIN or SIGINT or SIGTERM signal,
         * stop kni processing
         */
        if (signum == SIGRTMIN || signum == SIGINT || signum == SIGTERM) {
                printf("\nSIGRTMIN/SIGINT/SIGTERM received. "
                        "KNI processing stopping.\n");
                rte_atomic32_inc(&kni_stop);
                return;
        }
}

static void
ac_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
        unsigned i;

        if (pkts == NULL)
                return;

        for (i = 0; i < num; i++) {
                rte_pktmbuf_free(pkts[i]);
                pkts[i] = NULL;
        }
}

// not support vlan now
static int do_udp_tunnel(struct rte_mbuf *mb)
{
        struct ac_tunnel_header *h;
        struct rte_ether_hdr *inner_eth_hdr;
        struct ac_fwd_entry *entry;
        struct ac_config *acfg = &g_ac_conf;
        int index;
        uint64_t cycle = rte_get_tsc_cycles();
#define MIN_SIZE (AC_TUNNEL_HEAD_SIZE + sizeof(*inner_eth_hdr))

        if (mb->data_len < MIN_SIZE)
                return 1;

        h = rte_pktmbuf_mtod(mb, struct ac_tunnel_header *);
        inner_eth_hdr = (struct rte_ether_hdr *)(h+1);
        index = rte_hash_lookup(acfg->hash_handle, inner_eth_hdr->s_addr.addr_bytes);
        if (unlikely(index < 0)) {
                // create table
                index = rte_hash_add_key(acfg->hash_handle, inner_eth_hdr->s_addr.addr_bytes);
                if (index < 0) {
                        RTE_LOG(ERR, APP, "hash add key fail on lcore: %d\n", rte_lcore_id());
                        return 1;
                }

                entry = acfg->hash_map[index];
                rte_memcpy(entry->device_smac.addr_bytes, inner_eth_hdr->s_addr.addr_bytes, 6);
                rte_memcpy(entry->client_smac.addr_bytes, h->eth_hdr.s_addr.addr_bytes, 6);
                entry->client_sip = h->ipv4_hdr.src_addr;
                entry->client_sudpp = h->udp_hdr.src_port;
                entry->touch_cycle = cycle;
                entry->check_cycle = cycle + rte_get_tsc_hz() / 2; // 0.5s
                entry->rx_pkts = 1;
        } else {
                // update or ignore
                entry = acfg->hash_map[index];
                entry->touch_cycle = cycle;
                if (entry->touch_cycle > entry->check_cycle) {
                        // need check
                        if (memcmp(entry->client_smac.addr_bytes, h->eth_hdr.s_addr.addr_bytes, 6)) {
                                rte_memcpy(entry->client_smac.addr_bytes, h->eth_hdr.s_addr.addr_bytes, 6);
                                entry->rx_pkts = 1;
                        }

                        if (entry->client_sip != h->ipv4_hdr.src_addr) {
                                entry->client_sip = h->ipv4_hdr.src_addr;
                                entry->rx_pkts = 1;
                        }

                        if (entry->client_sudpp != h->udp_hdr.src_port) {
                                entry->client_sudpp = h->udp_hdr.src_port;
                                entry->rx_pkts = 1;
                        }

                        entry->check_cycle = cycle + rte_get_tsc_hz() / 2; // 0.5s
                }
                entry->rx_pkts++;
        }

        rte_pktmbuf_adj(mb, (uint16_t)sizeof(*h));

        return 0;
}

// 0: send to output, -1: send to kernel
static int
ac_do_other(struct rte_mbuf *mb)
{
        struct ac_tunnel_header *h;
        struct rte_ether_hdr *eth_hdr;
        struct ac_fwd_entry *entry;
        int index, data_len;
        struct ac_config *acfg = &g_ac_conf;

        eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
        index = rte_hash_lookup(acfg->hash_handle, eth_hdr->d_addr.addr_bytes);
        if (index < 0) {
                return 1;
        }

        entry = acfg->hash_map[index];
        data_len = mb->data_len;
        h = (struct ac_tunnel_header *)rte_pktmbuf_prepend(mb, sizeof(*h));
        if (unlikely(h == NULL)) {
                rte_exit(EXIT_FAILURE, "rte_pktmbuf_prepend fail!");
        }

        rte_memcpy(h, &acfg->header_templete, sizeof(*h));
        h->udp_hdr.dgram_len = rte_cpu_to_be_16(data_len);
        h->udp_hdr.dst_port = entry->client_sudpp;

        h->ipv4_hdr.total_length = rte_cpu_to_be_16(data_len + sizeof(struct rte_ipv4_hdr));
        h->ipv4_hdr.dst_addr = entry->client_sip;
        rte_memcpy(h->eth_hdr.d_addr.addr_bytes, entry->device_smac.addr_bytes, 6);

        mb->ol_flags = PKT_TX_OUTER_IP_CKSUM | PKT_TX_OUTER_UDP_CKSUM;
        if (data_len+sizeof(*h) > acfg->ac_mtu) {
                // UDP SEG
                mb->ol_flags |= PKT_TX_UDP_SEG;
                mb->tso_segsz = acfg->ac_mtu;
        }

        return 0;
}

static void
ac_tunnel_handler(struct ac_lcore_conf *lcore_conf)
{
        int ret;
        unsigned i, nb_tx, num, nb_txk, nb_txo, nb_txo_free;
        struct rte_mbuf *mbk[PKT_BURST_SZ]; //send to kernel
        struct rte_mbuf *mbo[PKT_BURST_SZ]; //send to line
        struct rte_mbuf *pkts_burst[PKT_BURST_SZ], *mb;
        struct rte_ring *kni_spring = g_ac_conf.kni_spring;
        struct rte_ring *kni_mpring = g_ac_conf.kni_mpring;
        int32_t f_stop = rte_atomic32_read(&kni_stop);
        int32_t f_pause;
        uint16_t port_id = 0;

        while (!f_stop) {
                f_pause = rte_atomic32_read(&kni_pause);
                num = rte_eth_rx_burst(port_id, lcore_conf->queue_id, pkts_burst, PKT_BURST_SZ);
                if (unlikely(num > PKT_BURST_SZ)) {
                        RTE_LOG(ERR, APP, "Error receiving from KNI\n");
                        return;
                }

                nb_txk = 0;
                nb_txo = 0;
                for (i=0; i<num; i++) {
                        mb = pkts_burst[i];
                        if (likely(i < num-1))
                                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i+1], void *));

                        // tunnel package
                        if (mb->ol_flags & PKT_RX_FDIR) {
                                ret = do_udp_tunnel(mb);
                        } else {
                                ret = ac_do_other(mb);
                        }

                        if (!ret) {
                                mbo[nb_txo++] = mb;
                        } else {
                                mbk[nb_txk++] = mb;
                        }
                }

                if (nb_txo < PKT_BURST_SZ && !f_pause) {
                        /* Fill kernel pkts to free line buffer */
                        nb_txo_free = PKT_BURST_SZ - nb_txo;
                        num = rte_ring_mc_dequeue_burst(kni_spring, (void**)(mbo+nb_txo), nb_txo_free, NULL);
                        nb_txo += num;
                }

                if (nb_txo) {
                        /* Xmit to line */
                        nb_tx = rte_eth_tx_burst(port_id, lcore_conf->queue_id, mbo, (uint16_t)nb_txo);
                        if (unlikely(nb_tx < nb_txo)) {
                                ac_burst_free_mbufs(&pkts_burst[nb_tx], nb_txo - nb_tx);
                                lcore_conf->tx_out_drop += nb_txo - nb_tx;
                        }
                }

                if (unlikely(f_pause)) {
                        if (nb_txk) {
                                /* Free mbufs not tx to kni interface */
                                ac_burst_free_mbufs(mbk, nb_txk);
                                g_ac_conf.kni_stats.rx_dropped += nb_txk;
                        }
                } else if (nb_txk) {
                        /* Enqueue line pkts to kernel fifo */
                        nb_tx = rte_ring_mp_enqueue_bulk(kni_mpring, (void**)mbk, nb_txk, NULL);
                        if (unlikely(nb_tx < nb_txk)) {
                                /* Free mbufs not tx to kni interface */
                                ac_burst_free_mbufs(&mbk[nb_txk], nb_txk - nb_tx);
                                g_ac_conf.kni_stats.rx_dropped += nb_txk - nb_tx;
                        }
                }

                f_stop = rte_atomic32_read(&kni_stop);
        }

        RTE_LOG(ERR, APP, "KNI device is stoped lcore: %d!\n", lcore_conf->lcore_id);
}

static void
ac_kni_handler(struct ac_lcore_conf *lcore_conf)
{
        struct rte_kni  *kni = g_ac_conf.kni;
        struct kni_interface_stats *kni_stats = &g_ac_conf.kni_stats;
        unsigned nb_tx, num;
        struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
        struct rte_ring *kni_spring = g_ac_conf.kni_spring;
        struct rte_ring *kni_mpring = g_ac_conf.kni_mpring;
        int32_t f_stop = rte_atomic32_read(&kni_stop);
        int32_t f_pause;

        while (!f_stop) {
                f_pause = rte_atomic32_read(&kni_pause);
                if (f_pause)
                        continue;

                num = rte_kni_rx_burst(kni, pkts_burst, PKT_BURST_SZ);
                if (num) {
                        nb_tx = rte_ring_sp_enqueue_bulk(kni_spring, (void**)pkts_burst, num, NULL);
                        if (unlikely(num > nb_tx)) {
                                /* Free mbufs not tx to kni interface */
                                ac_burst_free_mbufs(&pkts_burst[num], num - nb_tx);
                                kni_stats->rx_dropped += num - nb_tx;
                        }
                }

                num = rte_ring_sc_dequeue_burst(kni_mpring, (void**)pkts_burst, PKT_BURST_SZ, NULL);
                if (num) {
                        /* Burst tx to kni */
                        nb_tx = rte_kni_tx_burst(kni, pkts_burst, num);
                        if (nb_tx)
                                kni_stats->rx_packets += nb_tx;

                        // rte_kni_handle_request(g_ac_conf.kni); // need move to later
                        if (unlikely(nb_tx < num)) {
                                /* Free mbufs not tx to kni interface */
                                ac_burst_free_mbufs(&pkts_burst[num], num - nb_tx);
                                kni_stats->rx_dropped += num - nb_tx;
                        }
                }

                rte_kni_handle_request(kni);
                f_stop = rte_atomic32_read(&kni_stop);
        }

        RTE_LOG(ERR, APP, "KNI device is stoped lcore: %d!\n", lcore_conf->lcore_id);
}

static int
ac_main_loop(__rte_unused void *arg)
{
        uint16_t i;
        const unsigned lcore_id = rte_lcore_id();
        struct ac_lcore_conf *lcore_conf = NULL;

        for (i=0; i<AC_MAX_LCORE; i++) {
                if (g_ac_conf.lcore_conf[i].lcore_id == lcore_id) {
                        lcore_conf = &g_ac_conf.lcore_conf[i];
                        break;
                }
        }

        if (!lcore_conf)
                return -1;

        if (lcore_conf->type == AC_LCORE_TYPE_KNI) {
                RTE_LOG(INFO, APP, "Lcore %u to handler kni packets\n", lcore_id);
                ac_kni_handler(lcore_conf);
        } else if (lcore_conf->type == AC_LCORE_TYPE_TUNNEL) {
                RTE_LOG(INFO, APP, "Lcore %u to handler line packets\n", lcore_id);
                ac_tunnel_handler(lcore_conf);
        } else {
                RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);
        }

        return 0;
}

/* Display usage instructions */
static void
ac_print_usage(const char *prgname)
{
        RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -m -c [bitmask]"
                   "    -m : enable monitoring of port carrier state\n"
                   "    -c : lcore bitmask\n",
                   prgname);
}

/* Parse the arguments given in the command line of the application */
static int
ac_parse_args(int argc, char **argv)
{
        int opt;
        const char *prgname = argv[0];

        /* Disable printing messages within getopt() */
        opterr = 0;

        /* Parse command line */
        while ((opt = getopt(argc, argv, "mc:")) != -1) {
                switch (opt) {
                case 'm':
                        monitor_links = 1;
                        break;
                case 'c':
                        if (strlen(optarg) <= 0)
                                rte_exit(EXIT_FAILURE, "Num of operations is not provided");
                        g_ac_conf.lcore = strtol(optarg, NULL, 16);
                        break;

                default:
                        ac_print_usage(prgname);
                        rte_exit(EXIT_FAILURE, "Invalid option specified\n");
                }
        }

        return 0;
}

#if 0
static void test_queue(struct rte_ring *kni_mpring)
{
        struct person {
                const char *name;
                int age;
        };
        struct person buf[2] = {
                {.name = "zhutao", .age = 18},
                {.name = "yunxia", .age = 15}
        };
        struct person *p[2] = {NULL, NULL};

        //struct rte_ring *kni_mpring = g_ac_conf.kni_mpring;
        unsigned n = 0;

         n = rte_ring_mp_enqueue_bulk(kni_mpring, (void**)buf, 2, NULL);
         printf("enqueue n: %d, p: %p, %p\n", n, p, p[0]);

         n = rte_ring_sc_dequeue_burst(kni_mpring, (void**)p, 32, NULL);
         if (n)
                printf("dnqueue n: %d, p: %p\n", n, p[0]);
         else
                printf("dequeue none object.");
}
#endif

/* Initialize KNI subsystem */
static void
ac_init_kni(void)
{
        struct rte_ring *kni_spring, *kni_mpring;

        kni_mpring = rte_ring_create("ac_kni_mp", AC_KNI_FIFO_SIZE,
                                        rte_socket_id(), RING_F_SC_DEQ);

        kni_spring = rte_ring_create("ac_kni_sp", AC_KNI_FIFO_SIZE,
                                rte_socket_id(), RING_F_SP_ENQ);
        if (!kni_spring || !kni_mpring) {
                rte_exit(EXIT_FAILURE, "Crete kni ring fail!");
        }

        g_ac_conf.kni_mpring = kni_mpring;
        g_ac_conf.kni_spring = kni_spring;

        /* Invoke rte KNI init to preallocate the ports */
        rte_kni_init(0);
}

static inline uint32_t
ac_hash(const void *data, __rte_unused uint32_t data_len, __rte_unused uint32_t init_val)
{
        const unsigned char *mac_addr = data;
        const uint32_t *p = (const uint32_t*)(mac_addr + 2);

        return *p;
}

static void
ac_build_tunnel_templete(struct ac_config *acfg)
{
        struct ac_tunnel_header *header = &acfg->header_templete;
        struct rte_ether_hdr *eth_hdr = &header->eth_hdr;
        struct rte_ipv4_hdr *ipv4_hdr = &header->ipv4_hdr;
        struct rte_udp_hdr *udp_hdr = &header->udp_hdr;

        memset(header, 0, sizeof(*header));

        rte_memcpy(eth_hdr->s_addr.addr_bytes, acfg->ac_mac.addr_bytes, 6);
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        ipv4_hdr->version_ihl = 0x45;   // ipv4,header 20byte
        ipv4_hdr->type_of_service = 0x0;
        ipv4_hdr->packet_id     = 0x0;
        ipv4_hdr->fragment_offset = 0x0;
        ipv4_hdr->next_proto_id  = 17;  // UDP
        ipv4_hdr->time_to_live   = 64;
        ipv4_hdr->src_addr = rte_cpu_to_be_32(acfg->ac_sip);

        udp_hdr->src_port = rte_cpu_to_be_16(acfg->ac_sport);
}

static void
ac_flow_rule_init(uint16_t port)
{
        struct rte_flow_attr attr;

        struct rte_flow_item pattern[4];
        struct rte_flow_item_ipv4 ipv4_spec, ipv4_mask;
        struct rte_flow_item_udp udp_spec, udp_mask;

        struct rte_flow_action action[2];
        struct rte_flow_error error;
        struct rte_flow *flow;
        struct rte_flow_action_mark     mark;

        memset(&attr, 0, sizeof(attr));
        memset(action, 0, sizeof(action));
        memset(pattern, 0, sizeof(pattern));
        memset(&ipv4_spec, 0, sizeof(ipv4_spec));
        memset(&ipv4_mask, 0, sizeof(ipv4_mask));
        memset(&udp_spec, 0, sizeof(udp_spec));
        memset(&udp_mask, 0, sizeof(udp_mask));
        memset(&mark, 0, sizeof(mark));

        attr.ingress = 1;

        pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

        ipv4_spec.hdr.dst_addr = g_ac_conf.ac_sip;
        ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        pattern[1].spec = &ipv4_spec;
        pattern[1].mask = &ipv4_mask;

        udp_spec.hdr.dst_port = g_ac_conf.ac_sport;
        udp_spec.hdr.dst_port = 0xFFFF;
        pattern[2].spec = &udp_spec;
        pattern[2].mask = &udp_mask;

        pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

        action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
        mark.id = 2;                                    // mark 2
        action[0].conf = &mark;
        action[1].type = RTE_FLOW_ACTION_TYPE_END;

        flow = rte_flow_create(port, &attr, pattern, action, &error);
        if (!flow) {
                rte_exit(EXIT_FAILURE, "Create flow fdir fail!: %s", error.message);
        }

        RTE_LOG(INFO, APP, "Initialising flow rule %u ok\n", (unsigned)port);
}


/* Initialise a single port on an Ethernet device */
static void
ac_init_port(uint16_t port)
{
        int ret, i, nb_lcore = 0, step, offset;
        uint16_t nb_rxd = NB_RXD;
        uint16_t nb_txd = NB_TXD;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = kni_port_conf;
        struct ac_lcore_conf *lcore_conf;
        struct rte_hash_parameters ac_hash_params = {
                .name = "AC_HASH",
                .entries = AC_MAC_FWD_ENTRY_NUM,
                .key_len = sizeof(struct rte_ether_addr),
                .hash_func = ac_hash,
                .hash_func_init_val = 0,
                .socket_id = rte_socket_id(),
                .extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD |
                        RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
                        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
        };

        /* Initialise device and RX/TX queues */
        RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
        fflush(stdout);

        /*
         * use port [0, n]
         * 0:                   reserve
         * [1,(n-1)]:   udp tunnel
         * n:                   kni
         */
        memset(g_ac_conf.lcore_conf, 0, sizeof(g_ac_conf.lcore_conf));
        for (i=0; i<AC_MAX_LCORE; i++) {
                if (g_ac_conf.lcore & (((uint64_t)0x1)<<i)) {
                        lcore_conf = &g_ac_conf.lcore_conf[nb_lcore];
                        lcore_conf->lcore_id = i;
                        lcore_conf->queue_id = nb_lcore;
                        nb_lcore++;
                }
        }
        g_ac_conf.nb_lcore = nb_lcore;

        step = AC_MAC_FWD_ENTRY_NUM / nb_lcore;
        offset = 0;
        for (i=0; i<nb_lcore; i++) {
                lcore_conf = &g_ac_conf.lcore_conf[i];
                if (i == nb_lcore-1) {
                        lcore_conf->type = AC_LCORE_TYPE_KNI; // last core used for kni
                        continue;
                }

                lcore_conf->ageing_start_index = offset;
                lcore_conf->type = AC_LCORE_TYPE_TUNNEL;
                offset += step;
                lcore_conf->ageing_end_index = offset-1;
        }

        memcpy(g_ac_conf.ac_mac.addr_bytes, "\x3C\xFD\xFE\xD2\x6E\x64", 6);
        g_ac_conf.ac_sip = RTE_IPV4(192,4,47,76);
        g_ac_conf.ac_sport =  rte_cpu_to_be_16(2345);
        ac_build_tunnel_templete(&g_ac_conf);

        // init fwd table
        g_ac_conf.hash_handle = rte_hash_create(&ac_hash_params);
        if (!g_ac_conf.hash_handle) {
                rte_exit(EXIT_FAILURE, "Failed to create ac hash table!");
        }
        g_ac_conf.hash_map = rte_zmalloc("ac_hash",
                                          (sizeof(struct ac_fwd_entry) +
                                          sizeof(void*))
                                          * AC_MAC_FWD_ENTRY_NUM,  0);
        if (!g_ac_conf.hash_map) {
                rte_exit(EXIT_FAILURE,
                             "Failed to allocate memory for fdir hash map!");
        }

        /* layout: [pointer array: obj, obj, obj ....]*/
        offset = sizeof(void*) * AC_MAC_FWD_ENTRY_NUM;
        for (i=0; i<AC_MAC_FWD_ENTRY_NUM; i++) {
                g_ac_conf.hash_map[i] = (struct ac_fwd_entry*)((unsigned long)(g_ac_conf.hash_map) + offset);
                offset += sizeof(struct ac_fwd_entry);
        }

        ret = rte_eth_dev_info_get(port, &dev_info);
        if (ret != 0)
                rte_exit(EXIT_FAILURE,
                        "Error during getting device (port %u) info: %s\n",
                        port, strerror(-ret));

        /* configure tx offload */
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
                local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) ||
                !(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM))
                rte_exit(EXIT_FAILURE,
                        "Port%u not support OUTER IPv4 and UDP cksum offload\n", port);

        ret = rte_eth_dev_configure(port, nb_lcore, nb_lcore, &local_port_conf);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
                            (unsigned)port, ret);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
                                "for port%u (%d)\n", (unsigned)port, ret);

        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;

        for (i=0; i<nb_lcore; i++) {
                ret = rte_eth_rx_queue_setup(port, i, nb_rxd,
                        rte_eth_dev_socket_id(port), &rxq_conf, pktmbuf_pool);
                if (ret < 0)
                        rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
                                        "port%u (%d)\n", (unsigned)port, ret);

                txq_conf = dev_info.default_txconf;
                txq_conf.offloads = local_port_conf.txmode.offloads;
                ret = rte_eth_tx_queue_setup(port, i, nb_txd,
                        rte_eth_dev_socket_id(port), &txq_conf);
                if (ret < 0)
                        rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
                                        "port%u (%d)\n", (unsigned)port, ret);
        }

        ac_flow_rule_init(port);

        ret = rte_eth_dev_start(port);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
                                                (unsigned)port, ret);

        if (promiscuous_on) {
                ret = rte_eth_promiscuous_enable(port);
                if (ret != 0)
                        rte_exit(EXIT_FAILURE,
                                "Could not enable promiscuous mode for port%u: %s\n",
                                port, rte_strerror(-ret));
                RTE_LOG(INFO, APP, "Enable promiscuous on port %u\n", (unsigned)port);
        }
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t portid)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
        uint8_t count, ports_up, print_flag = 0;
        struct rte_eth_link link;
        int ret;

        printf("\nChecking link status\n");
        fflush(stdout);
        for (count = 0; count <= MAX_CHECK_TIME; count++) {
                ports_up = 1;
                memset(&link, 0, sizeof(link));
                ret = rte_eth_link_get_nowait(portid, &link);
                if (ret < 0) {
                        ports_up = 0;
                        if (print_flag == 1)
                                printf("Port %u link get failed: %s\n",
                                        portid, rte_strerror(-ret));
                        continue;
                }
                /* print link status if flag set */
                if (print_flag == 1) {
                        if (link.link_status) {
                                printf(
                                "Port%d Link Up - speed %uMbps - %s\n",
                                        portid, link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                                ("full-duplex") : ("half-duplex\n"));
                                break;
                        } else {
                                printf("Port %d Link Down\n", portid);
                                continue;
                        }
                }
                /* clear all_ports_up flag if any link down */
                if (link.link_status == ETH_LINK_DOWN) {
                        ports_up = 0;
                        break;
                }

                /* after finally printing all link status, get out */
                if (print_flag == 1)
                        break;

                if (ports_up == 0) {
                        printf(".");
                        fflush(stdout);
                        rte_delay_ms(CHECK_INTERVAL);
                }

                /* set the print_flag if all ports up or timeout */
                if (ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
                        print_flag = 1;
                        printf("done\n");
                }
        }
}

static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
        if (kni == NULL || link == NULL)
                return;

        if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
                RTE_LOG(INFO, APP, "%s NIC Link is Up %d Mbps %s %s.\n",
                        rte_kni_get_name(kni),
                        link->link_speed,
                        link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
                        link->link_duplex ?  "Full Duplex" : "Half Duplex");
        } else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
                RTE_LOG(INFO, APP, "%s NIC Link is Down.\n",
                        rte_kni_get_name(kni));
        }
}

/*
 * Monitor the link status of all ports and update the
 * corresponding KNI interface(s)
 */
static void *
monitor_all_ports_link_status(void *arg)
{
        uint16_t portid = 0;
        struct rte_eth_link link;
        struct rte_kni *kni = g_ac_conf.kni;
        int prev;
        (void) arg;
        int ret;

        while (monitor_links) {
                rte_delay_ms(500);
                memset(&link, 0, sizeof(link));
                ret = rte_eth_link_get_nowait(portid, &link);
                if (ret < 0) {
                        RTE_LOG(ERR, APP,
                                "Get link failed (port %u): %s\n",
                                portid, rte_strerror(-ret));
                        continue;
                }

                prev = rte_kni_update_link(kni,
                                link.link_status);
                log_link_state(kni, prev, &link);
        }
        return NULL;
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
        int ret;
        uint16_t nb_rxd = NB_RXD;
        struct rte_eth_conf conf;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_rxconf rxq_conf;

        if (!rte_eth_dev_is_valid_port(port_id)) {
                RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

        /* Stop specific port */
        rte_eth_dev_stop(port_id);

        memcpy(&conf, &kni_port_conf, sizeof(conf));
        /* Set new MTU */
        if (new_mtu > RTE_ETHER_MAX_LEN)
                conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
        else
                conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

        /* mtu + length of header + length of FCS = max pkt length */
        conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
                                                        KNI_ENET_FCS_SIZE;
        ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
        if (ret < 0) {
                RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
                return ret;
        }

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, NULL);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
                                "for port%u (%d)\n", (unsigned int)port_id,
                                ret);

        ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0) {
                RTE_LOG(ERR, APP,
                        "Error during getting device (port %u) info: %s\n",
                        port_id, strerror(-ret));

                return ret;
        }

        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
        if (ret < 0) {
                RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
                                port_id);
                return ret;
        }

        /* Restart specific port */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
                RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
                return ret;
        }

        return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
        int ret = 0;

        if (!rte_eth_dev_is_valid_port(port_id)) {
                RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
                                        port_id, if_up ? "up" : "down");

        rte_atomic32_inc(&kni_pause);

        if (if_up != 0) { /* Configure network interface up */
                rte_eth_dev_stop(port_id);
                ret = rte_eth_dev_start(port_id);
        } else /* Configure network interface down */
                rte_eth_dev_stop(port_id);

        rte_atomic32_dec(&kni_pause);

        if (ret < 0)
                RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

        return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
        char buf[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
        RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
        int ret = 0;

        if (!rte_eth_dev_is_valid_port(port_id)) {
                RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
        print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

        ret = rte_eth_dev_default_mac_addr_set(port_id,
                                        (struct rte_ether_addr *)mac_addr);
        if (ret < 0)
                RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
                        port_id);

        return ret;
}

static int
ac_kni_alloc(uint16_t port_id)
{
        struct rte_kni *kni;
        struct rte_kni_conf conf;
        int ret;

        /* Clear conf at first */
        memset(&conf, 0, sizeof(conf));

        snprintf(conf.name, RTE_KNI_NAMESIZE,
                                        "vEth%u", port_id);
        conf.group_id = port_id;
        conf.mbuf_size = MAX_PACKET_SZ;

        struct rte_kni_ops ops;
        struct rte_eth_dev_info dev_info;

        ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0)
                rte_exit(EXIT_FAILURE,
                        "Error during getting device (port %u) info: %s\n",
                        port_id, strerror(-ret));

        /* Get the interface default mac address */
        ret = rte_eth_macaddr_get(port_id,
                (struct rte_ether_addr *)&conf.mac_addr);
        if (ret != 0)
                rte_exit(EXIT_FAILURE,
                        "Failed to get MAC address (port %u): %s\n",
                        port_id, rte_strerror(-ret));

        rte_eth_dev_get_mtu(port_id, &conf.mtu);

        conf.min_mtu = dev_info.min_mtu;
        conf.max_mtu = dev_info.max_mtu;

        memset(&ops, 0, sizeof(ops));
        ops.port_id = port_id;
        ops.change_mtu = kni_change_mtu;
        ops.config_network_if = kni_config_network_interface;
        ops.config_mac_address = kni_config_mac_address;

        kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
        if (!kni)
                rte_exit(EXIT_FAILURE, "Fail to create kni for "
                                        "port: %d\n", port_id);
        g_ac_conf.kni = kni;

        return 0;
}

static int
ac_free_kni(uint16_t port_id)
{

        if (rte_kni_release(g_ac_conf.kni))
                        printf("Fail to release kni\n");

        g_ac_conf.kni = NULL;
        rte_eth_dev_stop(port_id);

        return 0;
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main(int argc, char** argv)
{
        int ret;
        uint16_t nb_sys_ports, port = 0;
        unsigned i;
        void *retval;
        pthread_t kni_link_tid;
        int pid;

        /* Associate signal_hanlder function with USR signals */
        signal(SIGUSR1, signal_handler);
        signal(SIGUSR2, signal_handler);
        signal(SIGRTMIN, signal_handler);
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        /* Initialise EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
        argc -= ret;
        argv += ret;

        /* Parse application arguments (after the EAL ones) */
        ret = ac_parse_args(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

        /* Create the mbuf pool */
        pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
                MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
        if (pktmbuf_pool == NULL) {
                rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
                return -1;
        }

        /* Get number of ports found in scan */
        nb_sys_ports = rte_eth_dev_count_avail();
        if (nb_sys_ports != 1 || !rte_eth_dev_is_valid_port(port))
                rte_exit(EXIT_FAILURE, "No supported Ethernet device found or port number > 1\n");


        /* Initialize KNI subsystem */
        ac_init_kni();

        /* Initialise each port */
        ac_init_port(port);
        ac_kni_alloc(port);

        check_all_ports_link_status(0);

        pid = getpid();
        RTE_LOG(INFO, APP, "========================\n");
        RTE_LOG(INFO, APP, "KNI Running\n");
        RTE_LOG(INFO, APP, "kill -SIGUSR1 %d\n", pid);
        RTE_LOG(INFO, APP, "    Show KNI Statistics.\n");
        RTE_LOG(INFO, APP, "kill -SIGUSR2 %d\n", pid);
        RTE_LOG(INFO, APP, "    Zero KNI Statistics.\n");
        RTE_LOG(INFO, APP, "========================\n");
        fflush(stdout);

        ret = rte_ctrl_thread_create(&kni_link_tid,
                                     "KNI link status check", NULL,
                                     monitor_all_ports_link_status, NULL);
        if (ret < 0)
                rte_exit(EXIT_FAILURE,
                        "Could not create link status thread!\n");

        /* Launch per-lcore function on every lcore */
        rte_eal_mp_remote_launch(ac_main_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(i) {
                if (rte_eal_wait_lcore(i) < 0)
                        return -1;
        }
        monitor_links = 0;
        pthread_join(kni_link_tid, &retval);

        /* Release resources */
        ac_free_kni(port);

        return 0;
}
