#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>
#include <malloc.h>

#include <rte_atomic.h>
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
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "basic_types.h"
#include "utility.h"
#include "router_conf.h"
#include "net.h"
#include "cpu_ticks.h"

#define TARGET_TX_RATE (10000000)

static struct router_conf *router_conf;
static u32 num_mac_addrs;
static u64 cpu_ticks_freq;

struct io_state {
    u64 num_packets_recv;
    u64 num_bursts_recv;
    u64 num_packets_send;
    u64 num_bursts_send;
    u64 num_packets_drop;

    u64 last_num_packets_recv;
    u64 last_num_bursts_recv;
    u64 last_num_packets_send;
    u64 last_num_bursts_send;
    u64 last_num_packets_drop;
} __rte_cache_aligned;

static struct io_state io_states[MAX_CPUS];

#define DEFAULT_IP_SRC_ADDR ((192 << 24) | (168 << 16) | (0 << 8) | 1)
#define DEFAULT_IP_DST_ADDR ((192 << 24) | (168 << 16) | (0 << 8) | 2)

#define DEFAULT_UDP_SRC_PORT (1024)
#define DEFAULT_UDP_DST_PORT (1024)

#define DEFAULT_PACKET_LENGTH (60)

char header[sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + 10];

static void build_header(void)
{
    struct ether_hdr *eth_hdr = (struct ether_hdr *)header;
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));
    struct udp_hdr *udp_hdr = (struct udp_hdr *)((char *)ip_hdr + sizeof(struct ipv4_hdr));

    u16 packet_length = DEFAULT_PACKET_LENGTH;

    /*
     * initialize Ethernet header
     */
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    /*
     * initialize UDP header
     */
    udp_hdr->src_port = DEFAULT_UDP_SRC_PORT;
    udp_hdr->dst_port = DEFAULT_UDP_DST_PORT;
    udp_hdr->dgram_len = rte_cpu_to_be_16((u16)(packet_length - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr)));
    udp_hdr->dgram_cksum = 0; /* no UDP checksum */

    /*
     * initialize IP header
     */
    ip_hdr->src_addr = DEFAULT_IP_SRC_ADDR;
    ip_hdr->dst_addr = DEFAULT_IP_DST_ADDR;
    ip_hdr->version_ihl = 0x40 | 0x05;
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->packet_id = 0;
    ip_hdr->total_length = rte_cpu_to_be_16((u16)(packet_length - sizeof(struct ether_hdr)));

    /*
     * compute IP header checksum
     */
    u16 *ptr16 = (u16*)ip_hdr;
    u32 ip_cksum;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
    ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

    /*
     * reduce 32 bit checksum to 16 bits and complement it
     */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
        ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x00005555;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;
    ip_hdr->hdr_checksum = (u16)ip_cksum;
}

static void build_packet(u8 port_id, u32 *seed, u32 *ipaddr_seed, struct rte_mbuf *packet)
{
    u16 packet_length = DEFAULT_PACKET_LENGTH;

    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));
    struct udp_hdr *udp_hdr = (struct udp_hdr *)((char *)ip_hdr + sizeof(struct ipv4_hdr));
    char *payload = (char *)((char *)udp_hdr + sizeof(struct udp_hdr));

    rte_memcpy(rte_pktmbuf_mtod(packet, char *), 
               header, 
               sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    memset(payload, 0, packet_length - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr));

    /* get_mac_addr(partition_id, port_id, &eth_hdr->s_addr); */
    /* get_mac_addr(dst_partition_id, dst_port_id, &eth_hdr->d_addr); */
    /* /\* eth_hdr->d_addr.addr_bytes[0] = 0xa0; *\/ */
    /* /\* eth_hdr->d_addr.addr_bytes[1] = 0x36; *\/ */
    /* /\* eth_hdr->d_addr.addr_bytes[2] = 0x9f; *\/ */
    /* /\* eth_hdr->d_addr.addr_bytes[3] = 0x; *\/ */
    /* /\* eth_hdr->d_addr.addr_bytes[4] = 0xa0; *\/ */
    /* /\* eth_hdr->d_addr.addr_bytes[5] = 0xa0; *\/ */
    rte_eth_macaddr_get(port_id, &eth_hdr->s_addr);

    u64 macaddr = ((u64)fastrand(seed) & 0xFFFF) |
        (((u64)fastrand(seed) & 0xFFFF) << 16) |
        (((u64)fastrand(seed) & 0xFFFF) << 32);
    eth_hdr->d_addr.addr_bytes[5] = macaddr & 0xFF; macaddr >>= 8;
    eth_hdr->d_addr.addr_bytes[4] = macaddr & 0xFF; macaddr >>= 8;
    eth_hdr->d_addr.addr_bytes[3] = macaddr & 0xFF; macaddr >>= 8;
    eth_hdr->d_addr.addr_bytes[2] = macaddr & 0xFF; macaddr >>= 8;
    eth_hdr->d_addr.addr_bytes[1] = macaddr & 0xFF; macaddr >>= 8;
    eth_hdr->d_addr.addr_bytes[0] = macaddr & 0xFF;

    ip_hdr->src_addr = ((u32)fastrand(ipaddr_seed)) | ((u32)fastrand(ipaddr_seed) << 16);
    ip_hdr->dst_addr = ((u32)fastrand(ipaddr_seed)) | ((u32)fastrand(ipaddr_seed) << 16);

    /*
     * compute IP header checksum
     */
    u16 *ptr16 = (u16*)ip_hdr;
    u32 ip_cksum;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
    ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

    /*
     * reduce 32 bit checksum to 16 bits and complement it
     */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
        ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x00005555;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;
    ip_hdr->hdr_checksum = (u16)ip_cksum;

    packet->pkt.data_len = packet_length;
    packet->pkt.next = NULL; /* last segment of packet */
    packet->pkt.nb_segs = 1;
    packet->pkt.pkt_len = packet_length;
    packet->ol_flags = 0;
}

static int netbench_client(void *arg)
{
    unsigned cpu_id = rte_lcore_id(), socket_id = rte_socket_id();
    u8 port_id;
    u16 queue_id;

    unsigned i, round, dst_port_id = 0;
    unsigned quota = TARGET_TX_RATE;

    unsigned macaddr_index = 0;
    unsigned seed = MAC_ADDR_SEED;
    unsigned ipaddr_seed = 0xabcdef;

    struct io_state *io_state = &io_states[cpu_id];
    struct rte_mbuf *packet;

    u64 cpu_ticks_start = read_cpu_ticks(), cpu_ticks_now;
    double time_prev = 0, time_now;

    printf("client %d started, socket_id: %d\n", cpu_id, socket_id);

    for (round = 0; ; round = (round + 1) & 63) {
        for (port_id = 0; port_id < MAX_PORTS; port_id++) {
            if (router_conf->cpu_tx_queue_id[cpu_id][port_id] < 0)
                continue;
            queue_id = router_conf->cpu_tx_queue_id[cpu_id][port_id];

            if (quota > 0) {
                quota--; 
                
                packet = alloc_packet();
                build_packet(port_id, &seed, &ipaddr_seed, packet);
                if (++macaddr_index == num_mac_addrs) {
                    macaddr_index = 0;
                    seed = MAC_ADDR_SEED;
                }
                
                send_packet(port_id, queue_id, packet);
            }
        }


        if (round == 63) {
            u64 num_packets_send = 0;
            u64 num_packets_drop = 0;
            u64 num_bursts_send = 0;

            for (port_id = 0; port_id < MAX_PORTS; port_id++) {
                u64 queue_num_packets_send;
                u64 queue_num_packets_drop;
                u64 queue_num_bursts_send;

                get_send_queue_stats(port_id, cpu_id, 
                                     &queue_num_packets_send,
                                     &queue_num_packets_drop,
                                     &queue_num_bursts_send);
                num_packets_send += queue_num_packets_send;
                num_packets_drop += queue_num_packets_drop;
                num_bursts_send += queue_num_bursts_send;
            }
            io_state->num_packets_send = num_packets_send;
            io_state->num_bursts_send = num_bursts_send;
            io_state->num_packets_drop = num_packets_drop;

            cpu_ticks_now = read_cpu_ticks();
            time_now = (double)(cpu_ticks_now - cpu_ticks_start) / cpu_ticks_freq;

            if (time_now - time_prev >= 1.0) {
                if (cpu_id == 0) {
                    u64 num_packets_recv = 0;
                    u64 num_bursts_recv = 0;
                    u64 num_packets_send = 0;
                    u64 num_packets_drop = 0;
                    u64 num_bursts_send = 0;

                    for (i = 0; i < MAX_CPUS; i++) {
                        u64 count = io_states[i].num_packets_recv - io_states[i].last_num_packets_recv;
                        io_state[i].last_num_packets_recv += count;
                        num_packets_recv += count;

                        count = io_state[i].num_bursts_recv - io_state[i].last_num_bursts_recv;
                        io_state[i].last_num_bursts_recv += count;
                        num_bursts_recv += count;

                        count = io_state[i].num_packets_send - io_state[i].last_num_packets_send;
                        io_state[i].last_num_packets_send += count;
                        num_packets_send += count;

                        count = io_state[i].num_packets_drop - io_state[i].last_num_packets_drop;
                        io_state[i].last_num_packets_drop += count;
                        num_packets_drop += count;

                        count = io_state[i].num_bursts_send - io_state[i].last_num_bursts_send;
                        io_state[i].last_num_bursts_send += count;
                        num_bursts_send += count;
                    }

                    printf("%.2lf RecvTput=%.2lf Mpps, SendTput=%.2lf Mpps, DropTput=%.2lf Mpps\n",
                           time_now,
                           (double)num_packets_recv / (time_now - time_prev) / 1000000,
                           (double)num_packets_send / (time_now - time_prev) / 1000000,
                           (double)num_packets_drop / (time_now - time_prev) / 1000000);
                }

                time_prev = time_now;
                quota = TARGET_TX_RATE;
            }
        }
    }
}

/* static void generate_mac_addrs() */
/* { */
/*     u32 i; */
/*     u32 seed = MAC_ADDR_SEED; */

/*     mac_addr_array = (u64 *)malloc(num_mac_addrs * sizeof(u64)); */
/*     for (i = 0; i < num_mac_addrs; i++) { */
/*         u64 mac_addr = ((u64)fastrand(&seed) & 0xFFFF) | */
/*             (((u64)fastrand(&seed) & 0xFFFF) << 16) | */
/*             (((u64)fastrand(&seed) & 0xFFFF) << 32); */
/*         mac_addr_array[i] = mac_addr; */
/*     } */
/* } */

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("usage: %s num-mac-addrs router-conf-file\n", argv[0]);
        return 0;
    }

    num_mac_addrs = (u32)atoi(argv[1]);
    cpu_ticks_freq = get_cpu_ticks_freq();

    char *eal_argv[] = {
        argv[0],
        "-c", "FFF",
        "-n", "3",
    };
    int eal_argc = sizeof(eal_argv) / sizeof(eal_argv[0]);

    printf("initializing EAL\n");
    rte_set_log_level(RTE_LOG_NOTICE);
    if (rte_eal_init(eal_argc, eal_argv) < 0)
        rte_exit(EXIT_FAILURE, "invalid EAL arguments\n");

    router_conf = router_conf_init(argv[2]);

    /* printf("generating FIB entries\n"); */
    /* generate_mac_addrs(); */

    printf("initializing network\n");
    net_start(router_conf, 0);

    printf("building packet header\n");
    build_header();

    printf("starting node\n");
    memset(io_states, 0, sizeof(io_states));

    rte_eal_mp_remote_launch(netbench_client, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();

    return 0;
}
