#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_lcore.h>

#include "router_conf.h"
#include "utility.h"

static inline u32
parse_list(char *str)
{
    u32 mask = 0;
    char *p = strchr(str, ',');

    while (p) {
        *p = 0;
        mask |= 1ULL << atoi(str);
        str = p + 1;
        p = strchr(str, ',');
    }
    mask |= 1U << atoi(str);

    return mask;
}

struct router_conf *
router_conf_init(char *router_conf_file)
{
    struct router_conf *router_conf = (struct router_conf *)malloc(sizeof(struct router_conf));
    memset(router_conf, 0, sizeof(struct router_conf));
    memset(router_conf->port_rx_queue_cpu_id, -1, sizeof(router_conf->port_rx_queue_cpu_id));
    memset(router_conf->port_tx_queue_cpu_id, -1, sizeof(router_conf->port_tx_queue_cpu_id));
    memset(router_conf->cpu_tx_queue_id, -1, sizeof(router_conf->cpu_tx_queue_id));

    u8 port_id;
    u16 queue_id, tx_queue_id;
    unsigned num_cpus = get_num_cpus();
    unsigned cpu_id, socket_id;
    u8 i;

    struct conf_parser *cp = conf_parser_create(router_conf_file);
    char *str;

    str = conf_parser_get_option_value(cp, "router", "cpu_list");
    printf("cpu_list: %s\n", str);
    router_conf->enabled_cpus = parse_list(str);
    str = conf_parser_get_option_value(cp, "router", "port_list");
    printf("port_list: %s\n", str);
    router_conf->enabled_ports = parse_list(str);
    printf("enabled_ports: %d\n", router_conf->enabled_ports);

    /* str = conf_parser_get_option_value(cp, "router", "external_port_list"); */
    /* if (str) */
    /*     router_conf->external_port_mask = parse_list(str); */
    /* str = conf_parser_get_option_value(cp, "router", "internal_port_list"); */
    /* if (str) */
    /*     router_conf->internal_port_mask = parse_list(str); */

    tx_queue_id = 0;

    for (port_id = 0; port_id < MAX_PORTS; port_id++) {
        if (((router_conf->enabled_ports >> port_id) & 1) == 0)
            continue;

        char option[1000];
        sprintf(option, "port_%d_socket_id", (int)port_id);
        router_conf->port_socket_id[port_id] = (unsigned)atoi(conf_parser_get_option_value(cp, "router", option));

        sprintf(option, "port_%d_internal_id", (int)port_id);
        str = conf_parser_get_option_value(cp, "router", option);
        if (str)
            router_conf->port_internal_id[port_id] = (unsigned)atoi(str);

        for (cpu_id = 0; cpu_id < MAX_CPUS; cpu_id++) {
            if (((router_conf->enabled_cpus >> cpu_id) & 1) == 0)
                continue;
            if (rte_lcore_to_socket_id(cpu_id) != router_conf->port_socket_id[port_id])
                continue;
            router_conf->port_rx_queue_cpu_id[port_id][router_conf->port_num_rx_queues[port_id]] = cpu_id;
            router_conf->port_num_rx_queues[port_id]++;
        }
        router_conf->port_num_tx_queues[port_id] = __builtin_popcount(router_conf->enabled_cpus);
    }

    for (cpu_id = 0; cpu_id < MAX_CPUS; cpu_id++) {
        if (((router_conf->enabled_cpus >> cpu_id) & 1) == 0)
            continue;

        /* printf("before initialization\n"); */
        /* for (port_id = 0; port_id < MAX_PORTS; port_id++) */
        /*     printf("%d ", router_conf->cpu_tx_queue_id[cpu_id][port_id]); */
        /* printf("\n"); */

        for (port_id = 0; port_id < MAX_PORTS; port_id++) {
            if (((router_conf->enabled_ports >> port_id) & 1) == 0)
                continue;

            for (queue_id = 0; queue_id < MAX_CPUS; queue_id++) {
                if (router_conf->port_rx_queue_cpu_id[port_id][queue_id] == cpu_id) {
                    router_conf->cpu_rx_queues[cpu_id][router_conf->cpu_num_rx_queues[cpu_id]].port_id = port_id;
                    router_conf->cpu_rx_queues[cpu_id][router_conf->cpu_num_rx_queues[cpu_id]].queue_id = queue_id;
                    router_conf->cpu_num_rx_queues[cpu_id]++;
                    break;
                }
            }

            router_conf->port_tx_queue_cpu_id[port_id][tx_queue_id] = cpu_id;
            router_conf->cpu_tx_queue_id[cpu_id][port_id] = tx_queue_id;
        }

        tx_queue_id++;
    }

    return router_conf;
}

