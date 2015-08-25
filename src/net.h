#ifndef __NET_H__
#define __NET_H__

#include "basic_types.h"
#include "router_conf.h"

void 
net_start(struct router_conf *router_conf, int promiscuous);

void
net_set_burst_size(int rx_burst_size, int tx_burst_size);

void
net_set_mac_addr(struct router_conf *router_conf, u8 node_id);

struct rte_mbuf *
alloc_packet();

void 
free_packet(struct rte_mbuf *packet);

u16 
receive_packets(u8 port_id, u16 queue_id, struct rte_mbuf **packets, u16 num_packets_to_recv);

void 
send_packet(u8 port_id, u16 queue_id, struct rte_mbuf *packet);

void 
get_recv_queue_stats(u8 port_id, u16 queue_id, u64 *num_packets_recv, u64 *num_bursts_recv);

void 
get_send_queue_stats(u8 port_id, u16 queue_id, u64 *num_packets_send, u64 *num_packets_drop, u64 *num_bursts_send);

void
get_mac_addr(u8 partition_id, u8 port_id, struct ether_addr *addr);

#endif
