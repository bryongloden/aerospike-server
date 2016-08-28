/*
 * xdr_config.h
 *
 * Copyright (C) 2011-2016 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

/*
 *  Server configuration declarations for the XDR module
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "fault.h"
#include "util.h"

//Length definitions. This should be in sync with the server definitions.
//It is bad that we are not using a common header file for all this.
#define CLUSTER_MAX_SZ		128
#define NAMESPACE_MAX_SZ	32
#define NAMESPACE_MAX_NUM	32

/* Configuration parser switch() case identifiers. The server (cfg.c) needs to
 * see these. The server configuration parser and the XDR configuration parser
 * will care about different subsets of these options. Order is not important,
 * other than for organizational sanity.
 */
typedef enum {
	// Generic:
	// Token not found:
	XDR_CASE_NOT_FOUND,
	// Alternative beginning of parsing context:
	XDR_CASE_CONTEXT_BEGIN,
	// End of parsing context:
	XDR_CASE_CONTEXT_END,

	// Top-level options:
	XDR_CASE_NAMESPACE_BEGIN,
	XDR_CASE_XDR_BEGIN,

	// Namespace options:
	XDR_CASE_NS_ENABLE_XDR,
	XDR_CASE_NS_XDR_REMOTE_DATACENTER,
	XDR_CASE_NS_MAX_TTL,
	XDR_CASE_NS_STORAGE_ENGINE_BEGIN,
	XDR_CASE_NS_SET_BEGIN,

	// Namespace storage options:
	XDR_CASE_NS_STORAGE_MEMORY,
	XDR_CASE_NS_STORAGE_SSD,
	XDR_CASE_NS_STORAGE_DEVICE,
	XDR_CASE_NS_STORAGE_KV,

	// Main XDR options:
	XDR_CASE_ENABLE_XDR,
	XDR_CASE_DIGESTLOG_PATH,
	XDR_CASE_ERRORLOG_PATH,
	XDR_CASE_INFO_PORT,
	XDR_CASE_DATACENTER_BEGIN,
	XDR_CASE_MAX_SHIP_THROUGHPUT,
	XDR_CASE_MAX_SHIP_BANDWIDTH,
	XDR_CASE_HOTKEY_TIME_MS,
	XDR_CASE_FORWARD_XDR_WRITES,
	XDR_CASE_CLIENT_THREADS,
	XDR_CASE_WRITE_TIMEOUT,
	XDR_CASE_XDR_DELETE_SHIPPING_ENABLED,
	XDR_CASE_XDR_CHECK_DATA_BEFORE_DELETE,
	XDR_CASE_XDR_NSUP_DELETES_ENABLED,
	XDR_CASE_XDR_SHIP_BINS,
	XDR_CASE_XDR_SHIPPING_ENABLED,
	XDR_CASE_XDR_PIDFILE,
	XDR_CASE_XDR_READ_BATCH_SIZE,
	XDR_CASE_XDR_INFO_TIMEOUT,
	XDR_CASE_XDR_COMPRESSION_THRESHOLD,
	XDR_CASE_XDR_SHIP_DELAY,
	XDR_CASE_XDR_READ_THREADS,

	// Security options:
	XDR_CASE_SEC_CREDENTIALS_BEGIN,
	XDR_CASE_SEC_CRED_USERNAME,
	XDR_CASE_SEC_CRED_PASSWORD,

	// Remote datacenter options:
	XDR_CASE_DC_NODE_ADDRESS_PORT,
	XDR_CASE_DC_INT_EXT_IPMAP,
	XDR_CASE_DC_SECURITY_CONFIG_FILE,
	XDR_CASE_DC_USE_ALTERNATE_SERVICES
} xdr_cfg_case_id;

/* Configuration parser token plus case-identifier pair. The server (cfg.c)
 * needs to see this.
 */
typedef struct xdr_cfg_opt_s {
	const char*		tok;
	xdr_cfg_case_id	case_id;
} xdr_cfg_opt;

/* The various xdr_cfg_opt arrays. The server (cfg.c) needs to see these.
 */
extern const xdr_cfg_opt XDR_GLOBAL_OPTS[];
extern const xdr_cfg_opt XDR_SERVICE_OPTS[];
extern const xdr_cfg_opt XDR_OPTS[];
extern const xdr_cfg_opt XDR_DC_OPTS[];
extern const xdr_cfg_opt XDR_NS_OPTS[];
extern const xdr_cfg_opt XDR_NS_STORAGE_OPTS[];
extern const xdr_cfg_opt XDR_NS_SET_OPTS[];
extern const xdr_cfg_opt XDR_SEC_GLOBAL_OPTS[];
extern const xdr_cfg_opt XDR_SEC_CRED_OPTS[];

/* The various xdr_cfg_opt array counts. The server (cfg.c) needs to see these.
 */
extern const int NUM_XDR_GLOBAL_OPTS;
extern const int NUM_XDR_SERVICE_OPTS;
extern const int NUM_XDR_OPTS;
extern const int NUM_XDR_DC_OPTS;
extern const int NUM_XDR_NS_OPTS;
extern const int NUM_XDR_NS_STORAGE_OPTS;
extern const int NUM_XDR_NS_SET_OPTS;
extern const int NUM_XDR_SEC_GLOBAL_OPTS;
extern const int NUM_XDR_SEC_CRED_OPTS;

// Some static knobs shared between XDR and asd
#define XDR_TIME_ADJUST	300000 // (5 minutes) LST adjustment in node failure cases.

#define DC_MAX_NUM 32
typedef struct xdr_lastship_s {
	cf_node		node;
	uint64_t	time[DC_MAX_NUM];
} xdr_lastship_s;


// Config option in case the configuration value is changed
typedef struct xdr_new_config_s {
	bool	skip_outstanding;
} xdr_new_config;

//Config option which is maintained both by the server and the XDR module
typedef struct xdr_config {

	//This section is used by both the server and the XDR module
	bool	xdr_global_enabled;

	// Ring buffer configuration
	char 	*xdr_digestlog_path;
	uint64_t xdr_digestlog_file_size;
	bool 	xdr_digestlog_overwrite;
	bool	xdr_digestlog_persist;

	int	xdr_info_port;
	int	xdr_max_ship_throughput;
	int	xdr_max_ship_bandwidth;
	int	xdr_hotkey_time_ms;
	int	xdr_read_threads;       // Number threads which will read from server and ship records.
	int	xdr_write_timeout;
	int	xdr_client_threads;
	int	xdr_forward_xdrwrites;
	int xdr_internal_shipping_delay;
	int	xdr_conf_change_flag;
	xdr_new_config xdr_new_cfg;
	bool	xdr_shipping_enabled;
	bool	xdr_delete_shipping_enabled;
	bool	xdr_nsup_deletes_enabled;
	bool	xdr_ship_bins;
	int		xdr_info_request_timeout_ms;
	int		xdr_compression_threshold;
	bool	xdr_handle_failednode;
	bool	xdr_handle_linkdown;
} xdr_config;

// XDR states
typedef enum xdr_state_e {
	XDR_COMING_UP,
	XDR_DLOG_WRITER_UP,
	XDR_UP,
	XDR_GOING_DOWN,
	XDR_DOWN
} xdr_state;

// Prototypes
void xdr_config_defaults(xdr_config *c);

// Variables
extern const bool g_xdr_supported;
