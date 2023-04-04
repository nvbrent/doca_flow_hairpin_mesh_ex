/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dpdk_utils.h>
#include <sig_db.h>
#include <utils.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <doca_flow.h>

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>

DOCA_LOG_REGISTER(HAIRPIN_MESH_EX);

#define MAX_HT_ENTRIES 4096

typedef uint64_t session_key;

struct session_entry
{
	session_key key;

	uint8_t proto;
	rte_be32_t src_ip;
	rte_be32_t dst_ip;
	rte_be16_t src_port;
	rte_be16_t dst_port;

	rte_be32_t snat_src_ip;
	rte_be16_t snat_src_port;

	uint16_t ingress_port;
	uint16_t egress_port;

	struct doca_flow_pipe_entry *flow_entry;
};

struct per_port_config {
	struct doca_flow_port *doca_port;
	struct doca_flow_pipe *root_pipe;
	struct doca_flow_pipe *tcp_session_pipe;
	struct doca_flow_pipe *udp_session_pipe;
};

struct hairpin_mesh_app_config {
	struct application_dpdk_config dpdk_config;
	struct per_port_config *port_flows;
	struct rte_hash *sessions;
};

struct rte_hash_parameters session_ht_params = {
	.name = "session_ht",
	.entries = MAX_HT_ENTRIES,
	.key_len = sizeof(session_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.extra_flag = 0, // see RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
};

////////////////////////////////////////////////////////////////////////////////
// Signal Handling

volatile bool force_quit = false;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void install_signal_handler(void)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

////////////////////////////////////////////////////////////////////////////////
// RSS Packet Processing

static int
log_packet(const struct rte_mbuf *packet)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	uint16_t ether_type = htons(eth_hdr->ether_type);

	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		DOCA_LOG_DBG("Received IPV4");
	} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
		DOCA_LOG_DBG("received IPV6");
	}

	return 0;
}

#define MAX_RX_BURST_SIZE 256

void
example_burst_rx(uint16_t port_id, uint16_t queue_id)
{
	struct rte_mbuf *rx_packets[MAX_RX_BURST_SIZE];

	uint32_t lcore_id = rte_lcore_id();

	double tsc_to_seconds = 1.0 / (double)rte_get_timer_hz();

	while (!force_quit) {
		uint64_t t_start = rte_rdtsc();

		uint16_t nb_rx_packets = rte_eth_rx_burst(port_id, queue_id, rx_packets, MAX_RX_BURST_SIZE);
		for (int i=0; i<nb_rx_packets; i++) {
			log_packet(rx_packets[i]);
		}

		double sec = (double)(rte_rdtsc() - t_start) * tsc_to_seconds;

		if (nb_rx_packets) {
			printf("L-Core %d processed %d packets in %f seconds", lcore_id, nb_rx_packets, sec);
		}
	}
}

int
sample_lcore_func(void *lcore_args)
{
	uint32_t lcore_id = rte_lcore_id() - 1;
	uint16_t port_id = (uint16_t)lcore_id; // assumes 1-to-1 mapping
	uint16_t queue_id = 0; // assumes only 1 queue
	if (lcore_id < rte_eth_dev_count_avail())
		example_burst_rx(port_id, queue_id);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Store data in rte_hash

#if 0
void
sample_hash_ops(void)
{
	struct session_entry * entry = rte_zmalloc("sessions", sizeof(struct session_entry), RTE_CACHE_LINE_SIZE);
	entry->key = 0x1234567890ull;
	entry->proto = IPPROTO_UDP;
	entry->src_ip = RTE_BE32(0x01020304);
	entry->dst_ip = RTE_BE32(0x05060708);
	entry->src_port = RTE_BE16(1111);
	entry->dst_port = RTE_BE16(2222);

	rte_hash_add_key_data(ht, &entry->key, entry);
}
#endif

doca_error_t
apply_session_flow(
	struct hairpin_mesh_app_config *app_config, 
	struct session_entry *session)
{
	struct application_dpdk_config *dpdk_config = &app_config->dpdk_config;
	struct per_port_config *port_flows = &app_config->port_flows[session->ingress_port];

	struct doca_flow_match match = {
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP4,
			.l4_type_ext = (session->proto == IPPROTO_UDP) ? DOCA_FLOW_L4_TYPE_EXT_UDP : DOCA_FLOW_L4_TYPE_EXT_TCP,
			.ip4 = {
				.src_ip = session->src_ip,
				.dst_ip = session->dst_ip,
			},
			// TCP/UDP port match set below
		},
	};

	struct doca_flow_actions actions[] = {
		[0] = {
			.outer.ip4.src_ip = session->snat_src_ip,
			// TCP/UDP port action set below
		}
	};

	struct doca_flow_header_l4_port *match_l4_port = session->proto == IPPROTO_UDP ?
		&match.outer.udp.l4_port : &match.outer.tcp.l4_port;

	struct doca_flow_header_l4_port *action_l4_port = session->proto == IPPROTO_UDP ?
		&match.outer.udp.l4_port : &match.outer.tcp.l4_port;

	match_l4_port->src_port = session->src_port;
	match_l4_port->dst_port = session->dst_port;
	action_l4_port->src_port = session->src_port;

	uint16_t rss_queues[] = {
		dpdk_config->port_config.nb_ports + session->egress_port,
	};
	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_RSS,
		.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP | DOCA_FLOW_RSS_TCP,
		.rss_queues = rss_queues,
		.num_of_queues = 1,
	};

	struct doca_flow_pipe * pipe = session->proto == IPPROTO_TCP ?
		port_flows->tcp_session_pipe : port_flows->udp_session_pipe;
	
	doca_error_t res = doca_flow_pipe_add_entry(
		0, pipe, &match, actions, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, 
		&session->flow_entry);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Port %u: session %lu: Failed to create pipe entry: %s", 
			session->ingress_port, session->key, doca_get_error_string(res));
	}
	return res;
}

doca_error_t
inject_sample_sessions(
	struct hairpin_mesh_app_config *app_config)
{
	struct session_entry session = {};

	int n_sessions = 100;
	for (int i=0; i<n_sessions; i++) {
		session.key = i+1;
		session.ingress_port = i % app_config->dpdk_config.port_config.nb_ports;
		session.egress_port = (i + 1) % app_config->dpdk_config.port_config.nb_ports;
		session.proto = (i < n_sessions/2) ? IPPROTO_UDP : IPPROTO_TCP;
		session.src_ip = RTE_BE32(0x10101010 + i);
		session.dst_ip = RTE_BE32(0x20101010 + i);
		session.src_port = RTE_BE16(100 + i);
		session.dst_port = RTE_BE16(200 + i);
		session.snat_src_ip = RTE_BE32(0x30101010 + i);
		session.snat_src_port = RTE_BE16(300 + i);
		doca_error_t res = apply_session_flow(app_config, &session);
		if (res != DOCA_SUCCESS)
			return res;
	}
	return DOCA_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Parsing args with argp

static doca_error_t
argp_isolated_mode_callback(void *config_voidp, void *param)
{
	struct hairpin_mesh_app_config *app_config = config_voidp;
	app_config->dpdk_config.port_config.isolated_mode = *(bool *)param;
	return DOCA_SUCCESS;
}

static void
app_register_argp_params(void)
{
	struct doca_argp_param * param = NULL;
	int ret = doca_argp_param_create(&param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(ret));
	doca_argp_param_set_short_name(param, "i");
	doca_argp_param_set_long_name(param, "isolated");
	doca_argp_param_set_description(param, "Selects isolated flow mode");
	doca_argp_param_set_callback(param, argp_isolated_mode_callback);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_BOOLEAN);
	ret = doca_argp_register_param(param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(ret));
	
	// Repeat for each parameter
}

////////////////////////////////////////////////////////////////////////////////
// DOCA Flow

static struct doca_flow_port *
port_init(uint16_t port_id)
{
	char port_id_str[128];
	snprintf(port_id_str, sizeof(port_id_str), "%d", port_id);

	struct doca_flow_port_cfg port_flows = {
		.port_id = port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str,
	};
	struct doca_flow_port * port = NULL;
	doca_error_t stat = doca_flow_port_start(&port_flows, &port);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to initialize doca flow port: %s", doca_get_error_string(stat));
		return NULL;
	}
	return port;
}

int
flow_init(struct hairpin_mesh_app_config *app_config)
{
	struct application_dpdk_config *dpdk_config = &app_config->dpdk_config;

	struct doca_flow_cfg flow_cfg = {
		.mode_args = dpdk_config->port_config.isolated_mode ? "vnf,hws,isolated" : "vnf,hws",
		.queues = dpdk_config->port_config.nb_queues,
		.resource.nb_counters = 1024,
	};
	doca_error_t stat = doca_flow_init(&flow_cfg);
	if (stat != DOCA_SUCCESS) {
		DOCA_LOG_ERR("failed to init doca: %s", doca_get_error_string(stat));
		return stat;
	}
	DOCA_LOG_DBG("DOCA flow init done");

	app_config->port_flows = rte_zmalloc("per_port_cfg",
		sizeof(struct per_port_config) * dpdk_config->port_config.nb_ports,
		RTE_CACHE_LINE_SIZE);

	for (uint16_t port_id = 0; port_id < dpdk_config->port_config.nb_ports; port_id++) {
		struct per_port_config *port_flows = &app_config->port_flows[port_id];
		port_flows->doca_port = port_init(port_id);
		if (port_flows->doca_port == NULL) {
			return -1;
		}
	}
	DOCA_LOG_DBG("DOCA ports init done");

#if 0
	// TODO: delete this after ensuring it's not needed
	/* pair the two ports together for hairpin forwarding */
	for (uint16_t port_id = 0; port_id + 1 < dpdk_config->port_config.nb_ports; port_id += 2) {	
		stat = doca_flow_port_pair(ports[port_id], ports[port_id + 1]);
		if (stat != DOCA_SUCCESS) {
			DOCA_LOG_ERR("DOCA Flow port pairing failed");
			return -1;
		}
	}
#endif

	DOCA_LOG_DBG("DOCA flow init done");
	return 0;
}

doca_error_t
create_session_pipe(
	struct hairpin_mesh_app_config *app_config,
	uint16_t port_id,
	uint8_t proto)
{
	struct per_port_config *port_flows = &app_config->port_flows[port_id];

	char name[80];
	snprintf(name, sizeof(name), "%s_session_pipe_%d",
		proto == IPPROTO_TCP ? "tcp" : "udp", port_id);

	struct doca_flow_match match = {
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP4,
			.ip4 = {
				.src_ip = UINT32_MAX,
				.dst_ip = UINT32_MAX,
			},
		},
	};
	if (proto == IPPROTO_UDP) {
		match.outer.udp.l4_port.src_port = UINT16_MAX;
		match.outer.udp.l4_port.dst_port = UINT16_MAX;
	} else {
		match.outer.tcp.l4_port.src_port = UINT16_MAX;
		match.outer.tcp.l4_port.dst_port = UINT16_MAX;
	}

	struct doca_flow_monitor mon = {
		.flags = DOCA_FLOW_MONITOR_COUNT | DOCA_FLOW_MONITOR_AGING,
		.aging = 5, // age timeout in seconds
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = name,
			.type = DOCA_FLOW_PIPE_BASIC,
		},
		.port = port_flows->doca_port,
		.match = &match,
		.monitor = &mon,
	};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_RSS,
		.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP | DOCA_FLOW_RSS_TCP,
		.num_of_queues = UINT32_MAX,
		// rss_queues to be set per entry
	};
	struct doca_flow_fwd miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};
	
	struct doca_flow_pipe ** pipe_out = proto == IPPROTO_UDP ?
		&port_flows->udp_session_pipe :
		&port_flows->tcp_session_pipe;

	doca_error_t res = doca_flow_pipe_create(
		&cfg, &fwd, &miss, pipe_out);
	
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Port %d: Failed to create pipe (%s): %s", 
			port_id, cfg.attr.name, doca_get_error_string(res));
	}
	return res;
}

doca_error_t
create_root_pipe_entry(
	struct hairpin_mesh_app_config *app_config,
	uint16_t port_id,
	uint8_t proto)
{
	struct per_port_config *port_flows = &app_config->port_flows[port_id];

	struct doca_flow_match match = {
		.outer = {
			.l3_type = DOCA_FLOW_L3_TYPE_IP4,
			.l4_type_ext = proto == IPPROTO_UDP ? DOCA_FLOW_L4_TYPE_EXT_UDP : DOCA_FLOW_L4_TYPE_EXT_TCP,
		},
	};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = proto == IPPROTO_UDP ?
			port_flows->udp_session_pipe :
			port_flows->tcp_session_pipe,
	};
	
	uint32_t queue = 0; // only the main thread
	uint32_t priority = 0; // the only priority

	struct doca_flow_pipe_entry *entry = NULL;
	doca_error_t res = doca_flow_pipe_control_add_entry(
		queue, priority, port_flows->root_pipe, 
		&match, NULL, NULL, NULL, NULL, &fwd, &entry);
	
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Port %d: Failed to create root pipe %s entry: %s", 
			port_id, proto==IPPROTO_UDP ? "UDP" : "TCP", doca_get_error_string(res));
	}

	return res;	
}

doca_error_t
create_root_pipe(
	struct hairpin_mesh_app_config *app_config,
	uint16_t port_id)
{
	struct per_port_config *port_flows = &app_config->port_flows[port_id];

	char name[80];
	snprintf(name, sizeof(name), "root_pipe_%d", port_id);

	struct doca_flow_pipe_cfg cfg = {
		.attr = {
			.name = name,
			.type = DOCA_FLOW_PIPE_CONTROL,
		},
		.port = port_flows->doca_port,
	};

	doca_error_t res = doca_flow_pipe_create(
		&cfg, NULL, NULL, &port_flows->root_pipe);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Port %d: Failed to create root pipe: %s", 
			port_id, doca_get_error_string(res));
		return res;
	}

	res = create_root_pipe_entry(app_config, port_id, IPPROTO_UDP);
	if (res != DOCA_SUCCESS) {
		return res;
	}
	res = create_root_pipe_entry(app_config, port_id, IPPROTO_TCP);
	return res;
}

int
pipes_init(struct hairpin_mesh_app_config *app_config)
{
	struct application_dpdk_config *dpdk_config = &app_config->dpdk_config;

	doca_error_t res = DOCA_SUCCESS;
	for (uint16_t port_id = 0; port_id < dpdk_config->port_config.nb_ports; port_id++) {
		res = create_session_pipe(app_config, port_id, IPPROTO_UDP);
		if (res != DOCA_SUCCESS)
			break;

		res = create_session_pipe(app_config, port_id, IPPROTO_TCP);
		if (res != DOCA_SUCCESS)
			break;

		res = create_root_pipe(app_config, port_id);
		if (res != DOCA_SUCCESS)
			break;
	}
	return res;
}

void
flow_destroy(uint16_t num_ports)
{
	struct rte_flow_error error = {};
	for (uint16_t port_id = 0; port_id < num_ports; port_id++)
	{
		// TODO: doca_flow_port_pipes_flush
		// TODO: doca_flow_port_stop
		rte_flow_flush(port_id, &error);
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
	}
}

int
main(int argc, char **argv)
{
	install_signal_handler();

	/* Create a logger backend that prints to the standard output */
	struct doca_logger_backend *stdout_logger = NULL;
	doca_error_t result = doca_log_create_file_backend(stdout, &stdout_logger);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	/* Parse cmdline/json arguments */
	struct hairpin_mesh_app_config app_config = {
		.dpdk_config = {
			.port_config = {
				.rss_support = true,
				.isolated_mode = false,
			},
			.reserve_main_thread = true,
		},
	};
	doca_argp_init("HairpinMeshExample", &app_config);
	doca_argp_set_dpdk_program(dpdk_init);
	app_register_argp_params();
	doca_argp_start(argc, argv);

	app_config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();
	app_config.dpdk_config.port_config.nb_hairpin_q = rte_eth_dev_count_avail();
	app_config.dpdk_config.port_config.nb_queues = rte_lcore_count();
	app_config.sessions = rte_hash_create(&session_ht_params);
	DOCA_LOG_INFO("Initialized HairpinMeshExample with %d cores, %d ports",
		rte_lcore_count(), rte_eth_dev_count_avail());

	result = dpdk_queues_and_ports_init(&app_config.dpdk_config);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	result = flow_init(&app_config);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	result = pipes_init(&app_config);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;
	
	result = inject_sample_sessions(&app_config);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(sample_lcore_func, &app_config, lcore_id);
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}
	
	flow_destroy(app_config.dpdk_config.port_config.nb_ports);
	doca_argp_destroy();

	return 0;
}
