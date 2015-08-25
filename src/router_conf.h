/* 
 * Packet-engine router configuration
 */

#ifndef __ROUTER_CONF_H__
#define __ROUTER_CONF_H__

#include "basic_types.h"
#include "common.h"

struct router_conf {
    unsigned enabled_cpus;
    unsigned enabled_ports;

    unsigned internal_port_mask;
    unsigned external_port_mask;

    unsigned port_internal_id[MAX_PORTS];

    unsigned port_socket_id[MAX_PORTS];

    /* forwarding paths conf */
    u16 port_num_rx_queues[MAX_PORTS];
    int port_rx_queue_cpu_id[MAX_PORTS][MAX_RX_QUEUES_PER_PORT];

    u16 port_num_tx_queues[MAX_PORTS];
    int port_tx_queue_cpu_id[MAX_PORTS][MAX_TX_QUEUES_PER_PORT];

    u16 cpu_num_rx_queues[MAX_CPUS];
    struct {
        u8 port_id;
        u16 queue_id;
    } cpu_rx_queues[MAX_CPUS][MAX_RX_QUEUES_PER_CPU];

    int cpu_tx_queue_id[MAX_CPUS][MAX_PORTS];
};

struct router_conf *
router_conf_init(char *router_conf_file);

#endif /* __ROUTER_CONF_H__ */

