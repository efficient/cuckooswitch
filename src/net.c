#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#include "common.h"
#include "net.h"

#define DEFAULT_NIC_RX_RING_SIZE (128)
#define DEFAULT_NIC_TX_RING_SIZE (512)

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define DEFAULT_NIC_RX_PTHRESH (8) /**< Default values of RX prefetch threshold reg. */
#define DEFAULT_NIC_RX_HTHRESH (8) /**< Default values of RX host threshold reg. */
#define DEFAULT_NIC_RX_WTHRESH (4) /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define DEFAULT_NIC_TX_PTHRESH (36) /**< Default values of TX prefetch threshold reg. */
#define DEFAULT_NIC_TX_HTHRESH (0)  /**< Default values of TX host threshold reg. */
#define DEFAULT_NIC_TX_WTHRESH (0)  /**< Default values of TX write-back threshold reg. */

/* Mempools */
#define MEMPOOL_CACHE_SIZE (256)
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define NUM_MBUF (MAX_PORTS * MAX_RX_QUEUES_PER_PORT * DEFAULT_NIC_RX_RING_SIZE \
                  + MAX_PORTS * MAX_TX_QUEUES_PER_PORT * DEFAULT_NIC_TX_RING_SIZE + \
                  + MAX_PORTS * MAX_CPUS * MAX_RX_BURST_SIZE            \
                  + MAX_CPUS * MEMPOOL_CACHE_SIZE)

static struct rte_eth_conf eth_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IPV4,
        },
    },
    .txmode = {
        .mq_mode = ETH_DCB_NONE,
    },
};

static struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = DEFAULT_NIC_RX_PTHRESH,
        .hthresh = DEFAULT_NIC_RX_HTHRESH,
        .wthresh = DEFAULT_NIC_RX_WTHRESH,
    },
    .rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = DEFAULT_NIC_TX_PTHRESH,
        .hthresh = DEFAULT_NIC_TX_HTHRESH,
        .wthresh = DEFAULT_NIC_TX_WTHRESH,
    },
    .tx_free_thresh = 0,
    .tx_rs_thresh = 0,
    .txq_flags = 0x0,
};

struct buffered_recv_queue {
    u64 num_packets_recv;
    u64 num_bursts_recv;
};

struct buffered_send_queue {
    struct rte_mbuf *buffered_packets[MAX_TX_BURST_SIZE];
    u16 num_buffered_packets;

    u64 num_packets_send;
    u64 num_packets_drop;
    u64 num_bursts_send;
} __rte_cache_aligned;

static struct rte_mempool *packet_pools[MAX_SOCKETS];
static struct buffered_recv_queue buffered_recv_queues[MAX_PORTS * MAX_RX_QUEUES_PER_PORT];
static struct buffered_send_queue buffered_send_queues[MAX_PORTS * MAX_TX_QUEUES_PER_PORT];
static u16 recv_burst_size, send_burst_size;

void 
net_start(struct router_conf *router_conf, int promiscuous)
{
    u8 port_id;
    u16 queue_id;
    unsigned socket_id, cpu_id;
    int ret;

    recv_burst_size = 32;
    send_burst_size = 32;

    for (socket_id = 0; socket_id < MAX_SOCKETS; socket_id++) {
        int enabled = 0;

        for (cpu_id = 0; cpu_id < MAX_CPUS; cpu_id++)
            if (((router_conf->enabled_cpus >> cpu_id) & 1) == 1 && rte_lcore_to_socket_id(cpu_id) == socket_id)
                enabled = 1;
        if (!enabled) continue;
            
        char name[32];

        rte_snprintf(name, sizeof(name), "packet_pool_%d", socket_id);
        printf("creating packet pool for socket %d\n", socket_id);
        printf("num_mbuf: %u\n", (unsigned)NUM_MBUF);
        packet_pools[socket_id] = rte_mempool_create(name,
                                                     NUM_MBUF,
                                                     MBUF_SIZE,
                                                     MEMPOOL_CACHE_SIZE,
                                                     sizeof(struct rte_pktmbuf_pool_private),
                                                     rte_pktmbuf_pool_init, NULL,
                                                     rte_pktmbuf_init, NULL,
                                                     socket_id,
                                                     0);
        if (packet_pools[socket_id] == NULL)
            rte_panic("cannot create packet pool on socket %d\n", socket_id);
    }

    printf("initializing the PMD driver\n");
    if (rte_ixgbe_pmd_init() < 0)
        rte_panic("cannot init igb_uio PMD\n");
    if (rte_eal_pci_probe() < 0)
        rte_panic("cannot probe PCI\n");

    for (port_id = 0; port_id < MAX_PORTS; port_id++) {
        struct rte_eth_link link;
        struct rte_mempool *pool;
        u16 num_rx_queues = router_conf->port_num_rx_queues[port_id];
        u16 num_tx_queues = router_conf->port_num_tx_queues[port_id];

        printf("port %d, #RXQ=%d, #TXQ=%d\n", port_id, num_rx_queues, num_tx_queues);
        if (num_rx_queues == 0 || num_tx_queues == 0)
            continue;
        ret = rte_eth_dev_configure(port_id,
                                    num_rx_queues,
                                    num_tx_queues,
                                    &eth_conf);
        if (ret < 0)
            rte_panic("cannot init NIC port %d (%d)\n", port_id, ret);

        for (queue_id = 0; queue_id < num_rx_queues; queue_id++) {
            cpu_id = router_conf->port_rx_queue_cpu_id[port_id][queue_id];
            printf("\tRXQ %d: cpu %d\n", queue_id, cpu_id);
            socket_id = rte_lcore_to_socket_id(cpu_id);
            pool = packet_pools[socket_id];
            ret = rte_eth_rx_queue_setup(port_id,
                                         queue_id,
                                         (u16)DEFAULT_NIC_RX_RING_SIZE,
                                         socket_id,
                                         &rx_conf,
                                         pool);
            if (ret < 0)
                rte_panic("cannot init RX queue %d for port %d (%d\n", queue_id, port_id, ret);
        }

        for (queue_id = 0; queue_id < num_tx_queues; queue_id++) {
            cpu_id = router_conf->port_tx_queue_cpu_id[port_id][queue_id];
            socket_id = rte_lcore_to_socket_id(cpu_id);
            ret = rte_eth_tx_queue_setup(port_id,
                                         queue_id,
                                         (u16)DEFAULT_NIC_TX_RING_SIZE,
                                         socket_id,
                                         &tx_conf);
            if (ret < 0)
                rte_panic("cannot init TX queue %d for port %d (%d)\n", queue_id, port_id, ret);
        }

        ret = rte_eth_dev_start(port_id);
        if (ret < 0)
            rte_panic("cannot start port %d (%d)\n", port_id, ret);
        if (promiscuous)
            rte_eth_promiscuous_enable(port_id);
        else
            rte_eth_promiscuous_disable(port_id);

        /* get link status */
        rte_eth_link_get(port_id, &link);
        if (link.link_status)
            fprintf(stderr, "port %d is UP (%d Mbps)\n", port_id, link.link_speed);
        else
            fprintf(stderr, "port %d is DOWN\n", port_id);
    }
}

void
net_set_burst_size(int rx_burst_size, int tx_burst_size)
{
    recv_burst_size = rx_burst_size;
    send_burst_size = tx_burst_size;
}

void
net_set_mac_addr(struct router_conf *router_conf, u8 parititon_id)
{
    u8 port_id;

    for (port_id = 0; port_id < MAX_PORTS; port_id++) {
        if (((router_conf->enabled_ports >> port_id) & 1) == 0)
            continue;

        printf("setting mac addr for port %d\n", port_id);

        struct ether_addr mac_addr;
        get_mac_addr(parititon_id, port_id, &mac_addr);

        rte_eth_dev_mac_addr_add(port_id, &mac_addr, 0);

        rte_eth_macaddr_get(port_id, &mac_addr);
        printf("mac addr of port %d: %x:%x:%x:%x:%x:%x\n", port_id, 
               mac_addr.addr_bytes[0],
               mac_addr.addr_bytes[1],
               mac_addr.addr_bytes[2],
               mac_addr.addr_bytes[3],
               mac_addr.addr_bytes[4],
               mac_addr.addr_bytes[5]);
    }
}

void
get_mac_addr(u8 parititon_id, u8 port_id, struct ether_addr *mac_addr)
{
    mac_addr->addr_bytes[0] = parititon_id;
    mac_addr->addr_bytes[1] = port_id;
    mac_addr->addr_bytes[2] = 0xde;
    mac_addr->addr_bytes[3] = 0xad;
    mac_addr->addr_bytes[4] = 0xbe;
    mac_addr->addr_bytes[5] = 0xef;
}

struct rte_mbuf *
alloc_packet()
{
    return rte_pktmbuf_alloc(packet_pools[rte_socket_id()]);
}

void
free_packet(struct rte_mbuf *packet)
{
    rte_pktmbuf_free(packet);
}

u16
receive_packets(u8 port_id, u16 queue_id, struct rte_mbuf **packets, u16 num_packets_to_recv)
{
    struct buffered_recv_queue *recv_queue = &buffered_recv_queues[port_id * MAX_RX_QUEUES_PER_PORT + queue_id];

    u16 num_packets_recv = rte_eth_rx_burst(port_id, queue_id,
                                            packets,
                                            num_packets_to_recv);
    recv_queue->num_packets_recv += num_packets_recv;
    recv_queue->num_bursts_recv++;
    
    return num_packets_recv;
}

inline void
send_packet(u8 port_id, u16 queue_id, struct rte_mbuf *packet)
{
    struct buffered_send_queue *send_queue = &buffered_send_queues[port_id * MAX_CPUS + queue_id];
    u16 i, num_buffered_packets = send_queue->num_buffered_packets;

    send_queue->buffered_packets[num_buffered_packets++] = packet;
    if (unlikely(num_buffered_packets >= send_burst_size)) {
        u16 num_packets = rte_eth_tx_burst(port_id, queue_id, 
                                           send_queue->buffered_packets, 
                                           (u16)num_buffered_packets);
        send_queue->num_packets_send += num_packets;
        send_queue->num_packets_drop += num_buffered_packets - num_packets;
        send_queue->num_bursts_send++;
        for (i = num_packets; i < num_buffered_packets; i++)
            rte_pktmbuf_free(send_queue->buffered_packets[i]);
        num_buffered_packets = 0;
    }
    send_queue->num_buffered_packets = num_buffered_packets;
}

void
get_recv_queue_stats(u8 port_id, u16 queue_id, u64 *num_packets_recv, u64 *num_bursts_recv)
{
    struct buffered_recv_queue *recv_queue = &buffered_recv_queues[port_id * MAX_RX_QUEUES_PER_PORT + queue_id];

    *num_packets_recv = recv_queue->num_packets_recv;
    *num_bursts_recv = recv_queue->num_bursts_recv;
}

void
get_send_queue_stats(u8 port_id, u16 queue_id, u64 *num_packets_send, u64 *num_packets_drop, u64 *num_bursts_send)
{
    struct buffered_send_queue *send_queue = &buffered_send_queues[port_id * MAX_TX_QUEUES_PER_PORT + queue_id];

    *num_packets_send = send_queue->num_packets_send;
    *num_packets_drop = send_queue->num_packets_drop;
    *num_bursts_send = send_queue->num_bursts_send;
}
