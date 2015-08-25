#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <tmmintrin.h>
#include <assert.h>

#include <rte_atomic.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "hashtable.h"
#include "basic_types.h"
#include "cpu_ticks.h"
#include "router_conf.h"
#include "net.h"
#include "utility.h"

#define HASH_ENTRIES (1ULL << 20)

static struct router_conf *router_conf;
static u32 num_eth_addrs;
static struct hashtable *table;

static struct rte_hash *dtable;
static u8 dst_port_table[HASH_ENTRIES];

static u64 cpu_ticks_freq;

struct buffered_tx_queue {
    struct rte_mbuf *packets[MAX_TX_BURST_SIZE];
    u16 num_packets;
} __rte_cache_aligned;

struct io_state {
    struct buffered_tx_queue tx_queues[MAX_PORTS];
    int tx_queue_id[MAX_PORTS];

    u64 num_packets_recv;
    u64 num_bursts_recv;
    u64 num_packets_send;
    u64 num_packets_drop;
    u64 num_bursts_send;
    
    u64 last_num_packets_recv;
    u64 last_num_bursts_recv;
    u64 last_num_packets_send;
    u64 last_num_packets_drop;
    u64 last_num_bursts_send;
} __rte_cache_aligned;

static struct io_state io_states[MAX_CPUS];

#define TX_BURST_DRAIN (300000ULL)
#define PREFETCH_OFFSET (3)

struct rte_hash_parameters l2fwd_hash_params = {
    .name = "l2fwd_hash",
    .entries = HASH_ENTRIES,
    .bucket_entries = 4,
    .key_len = 6,
    .hash_func = rte_hash_crc,
    .hash_func_init_val = 0,
    .socket_id = 0,
};

static inline void
send_packets(struct io_state *io_state, u8 port_id, u16 num_packets)
{
    struct buffered_tx_queue *tx_queue = &io_state->tx_queues[port_id];

    u16 i, num_packets_send = rte_eth_tx_burst(port_id, io_state->tx_queue_id[port_id],
                                               tx_queue->packets,
                                               num_packets);
    
    io_state->num_packets_send += num_packets_send;
    io_state->num_packets_drop += num_packets - num_packets_send;
    io_state->num_bursts_send++;

    for (i = num_packets_send; i < num_packets; i++)
        rte_pktmbuf_free(tx_queue->packets[i]);
}

static inline void
send_single_packet(struct io_state *io_state, u8 port_id, struct rte_mbuf *packet)
{
    struct buffered_tx_queue *tx_queue = &io_state->tx_queues[port_id];
    u16 i, num_packets = tx_queue->num_packets;

    tx_queue->packets[num_packets++] = packet;
    if (unlikely(num_packets >= MAX_TX_BURST_SIZE)) {
        /* u16 num_packets_send = rte_eth_tx_burst(port_id, io_state->tx_queue_id[port_id], */
        /*                                         tx_queue->packets, */
        /*                                         32); */
        /* io_state->num_packets_send += num_packets_send; */
        /* io_state->num_packets_drop += 32 - num_packets_send; */
        /* io_state->num_bursts_send++; */
        /* for (i = num_packets_send; i < num_packets; i++) */
        /*     rte_pktmbuf_free(tx_queue->packets[i]); */
        send_packets(io_state, port_id, num_packets);
        num_packets = 0;
    }
    tx_queue->num_packets = num_packets;
}

static int netbench_server(void *arg)
{
    unsigned cpu_id = rte_lcore_id(), socket_id = rte_socket_id();
    struct io_state *io_state = &io_states[cpu_id];
    
    u8 port_id;
    u16 queue_id;
    unsigned i, round;
    
    int packet_index, num_packets;
    struct rte_mbuf *packets[MAX_RX_BURST_SIZE];

    u64 cpu_ticks_start, cpu_ticks_last, cpu_ticks_now;
    double time_last = 0, time_now;

    for (port_id = 0; port_id < MAX_PORTS; port_id++)
        io_state->tx_queue_id[port_id] = router_conf->cpu_tx_queue_id[cpu_id][port_id];

    /* printf("cpu %d:\n", cpu_id); */
    /* printf("\t# rx queues: %d\n", router_conf->cpu_num_rx_queues[cpu_id]); */
    /* printf("\t"); */
    /* for (port_id = 0; port_id < MAX_PORTS; port_id++) { */
    /*     printf("port %d: tx_queue_id %d ", port_id, io_state->tx_queue_id[port_id]); */
    /* } */
    /* printf("\n"); */

    cpu_ticks_start = cpu_ticks_last = read_cpu_ticks();

    while (1) {
        cpu_ticks_now = read_cpu_ticks();

        if (unlikely(cpu_ticks_now - cpu_ticks_last) > TX_BURST_DRAIN) {
            /* for (port_id = 0; port_id < MAX_PORTS; port_id++) { */
            /*     if (io_state->tx_queues[port_id].num_packets == 0) */
            /*         continue; */
            /*     send_packets(io_state, port_id, io_state->tx_queues[port_id].num_packets); */
            /*     io_state->tx_queues[port_id].num_packets = 0; */
            /* } */

            if (cpu_id == 0) {
                time_now = (double)(cpu_ticks_now - cpu_ticks_start) / cpu_ticks_freq;
                if (time_now - time_last >= 1.0) {
                    u64 num_packets_recv = 0;
                    u64 num_bursts_recv = 0;
                    u64 num_packets_send = 0;
                    u64 num_packets_drop = 0;
                    u64 num_bursts_send = 0;

                    for (i = 0; i < MAX_CPUS; i++) {
                        u64 count = io_states[i].num_packets_recv - io_states[i].last_num_packets_recv;
                        io_states[i].last_num_packets_recv += count;
                        num_packets_recv += count;

                        count = io_states[i].num_bursts_recv - io_states[i].last_num_bursts_recv;
                        io_states[i].last_num_bursts_recv += count;
                        num_bursts_recv += count;

                        count = io_states[i].num_packets_send - io_states[i].last_num_packets_send;
                        io_states[i].last_num_packets_send += count;
                        num_packets_send += count;

                        count = io_states[i].num_packets_drop - io_states[i].last_num_packets_drop;
                        io_states[i].last_num_packets_drop += count;
                        num_packets_drop += count;

                        count = io_states[i].num_bursts_send - io_states[i].last_num_bursts_send;
                        io_states[i].last_num_bursts_send += count;
                        num_bursts_send += count;
                    }

                    printf("%.2lf RecvTput: %.2lf Mpps, SendTput: %.2lf Mpps, DropTput: %.2lf Mpps\n",
                           time_now,
                           (double)num_packets_recv / (time_now - time_last) / 1000000,
                           (double)num_packets_send / (time_now - time_last) / 1000000,
                           (double)num_packets_drop / (time_now - time_last) / 1000000);
                    time_last = time_now;
                }
            }
            cpu_ticks_last = cpu_ticks_now;
        }

        for (i = 0; i < router_conf->cpu_num_rx_queues[cpu_id]; i++) {
            port_id = router_conf->cpu_rx_queues[cpu_id][i].port_id;
            queue_id = router_conf->cpu_rx_queues[cpu_id][i].queue_id;

            num_packets = receive_packets(port_id, queue_id,
                                          packets,
                                          MAX_RX_BURST_SIZE);
            if (unlikely(num_packets == 0))
                continue;
            io_state->num_packets_recv += num_packets;
            io_state->num_bursts_recv++;

            struct rte_mbuf *packet;
            struct ether_hdr *hdr;
            u64 eth_addr_array[MAX_RX_BURST_SIZE];
            u16 dst_port_id_array[MAX_RX_BURST_SIZE];

            for (packet_index = 0; packet_index < num_packets; packet_index++)
                rte_prefetch0(rte_pktmbuf_mtod(packets[packet_index], void **));
            for (packet_index = 0; packet_index < num_packets; packet_index++) {
                packet = packets[packet_index];
                hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
                eth_addr_array[packet_index] =                                
                    (((u64)hdr->d_addr.addr_bytes[0]) << 40) |     
                    (((u64)hdr->d_addr.addr_bytes[1]) << 32) |     
                    (((u64)hdr->d_addr.addr_bytes[2]) << 24) |     
                    (((u64)hdr->d_addr.addr_bytes[3]) << 16) |     
                    (((u64)hdr->d_addr.addr_bytes[4]) <<  8) |     
                    (((u64)hdr->d_addr.addr_bytes[5]));           
                /* int ret = rte_hash_lookup(dtable, (const void *) &eth_addr_array[packet_index]); */
                /* assert(ret >= 0); */
                /* dst_port_id_array[packet_index] = dst_port_table[ret]; */
            }
            hashtable_lookup_multi(table, num_packets, eth_addr_array, dst_port_id_array);
            for (packet_index = 0; packet_index < num_packets; packet_index++) {
                assert(dst_port_id_array[packet_index] == (eth_addr_array[packet_index] & 1));
                send_single_packet(io_state, dst_port_id_array[packet_index], packets[packet_index]);
            }
        }
    }
}

static void generate_table()
{
    unsigned i, seed = MAC_ADDR_SEED;
    unsigned hashpower = 0;

    /* /\* while ((1ULL << hashpower) * HASHTABLE_BUCKET_NUM_ITEMS < num_eth_addrs) *\/ */
    /* /\*     hashpower++; *\/ */
    /* table = hashtable_create(18, NULL); */

    dtable = rte_hash_create(&l2fwd_hash_params);

    for (i = 0; i < num_eth_addrs; i++) {
        u64 key = ((u64)fastrand(&seed) & 0xFFFF) |
            (((u64)fastrand(&seed) & 0xFFFF) << 16) |
            (((u64)fastrand(&seed) & 0xFFFF) << 32);
        u16 value = (key & 1);

        /* hashtable_insert(table, key, value); */

        int ret = rte_hash_add_key(dtable, (void *) &key);
        if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Unable to add entry %u to the l2fwd hash\n", i);
        }
        dst_port_table[ret] = key & 1;
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("usage: %s router-conf-file num-eth-addrs\n", argv[0]);
        return 0;
    }

    num_eth_addrs = (u32)atoi(argv[2]);
    cpu_ticks_freq = get_cpu_ticks_freq();
 
    char *eal_argv[] = {
        argv[0],
        /* "-c", "FFFF", */
        "-c", "1",
        "-n", "4",
    };
    int eal_argc = sizeof(eal_argv) / sizeof(eal_argv[0]);

    printf("initializing EAL\n");
    rte_set_log_level(RTE_LOG_NOTICE);
    if (rte_eal_init(eal_argc, eal_argv) < 0)
        rte_exit(EXIT_FAILURE, "invalid EAL arguments\n");

    /* printf("initializing router conf\n"); */
    /* router_conf = router_conf_init(argv[1]); */

    printf("initializing forwarding table\n");
    generate_table();

    /* printf("initializing network\n"); */
    /* net_start(router_conf, 1); */

    /* printf("start server\n"); */
    /* memset(io_states, 0, sizeof(io_states)); */
    /* rte_eal_mp_remote_launch(netbench_server, NULL, CALL_MASTER); */
    /* rte_eal_mp_wait_lcore(); */

    return 0;
}
