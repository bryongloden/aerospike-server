/*
 * xdr_config.c
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
 *  Configuration file-related routines shared between the server and XDR.
 */

#include "xdr_config.h"

const xdr_cfg_opt XDR_GLOBAL_OPTS[] = {
		{ "namespace",						XDR_CASE_NAMESPACE_BEGIN },
		{ "xdr",							XDR_CASE_XDR_BEGIN }
};

const xdr_cfg_opt XDR_NS_OPTS[] = {
		{ "enable-xdr",						XDR_CASE_NS_ENABLE_XDR },
		{ "xdr-remote-datacenter",			XDR_CASE_NS_XDR_REMOTE_DATACENTER },
		{ "max-ttl",						XDR_CASE_NS_MAX_TTL },
		{ "storage-engine",					XDR_CASE_NS_STORAGE_ENGINE_BEGIN },
		{ "set",							XDR_CASE_NS_SET_BEGIN },
		{ "}",								XDR_CASE_CONTEXT_END }
};

const xdr_cfg_opt XDR_NS_STORAGE_OPTS[] = {
		{ "memory",							XDR_CASE_NS_STORAGE_MEMORY },
		{ "ssd",							XDR_CASE_NS_STORAGE_SSD },
		{ "device",							XDR_CASE_NS_STORAGE_DEVICE },
		{ "kv",								XDR_CASE_NS_STORAGE_KV },
		{ "}",								XDR_CASE_CONTEXT_END }
};

const xdr_cfg_opt XDR_NS_SET_OPTS[] = {
		{ "}",								XDR_CASE_CONTEXT_END }	// only thing that is of interest for
																	// XDR to skip over the set subsection
};

const xdr_cfg_opt XDR_OPTS[] = {
		{ "{",								XDR_CASE_CONTEXT_BEGIN },
		{ "enable-xdr",						XDR_CASE_ENABLE_XDR },
		{ "xdr-digestlog-path",				XDR_CASE_DIGESTLOG_PATH },
		{ "xdr-errorlog-path",				XDR_CASE_ERRORLOG_PATH },					// deprecated (3.8.0)
		{ "xdr-info-port",					XDR_CASE_INFO_PORT },
		{ "datacenter",						XDR_CASE_DATACENTER_BEGIN },
		{ "xdr-max-ship-throughput",		XDR_CASE_MAX_SHIP_THROUGHPUT },
		{ "xdr-max-ship-bandwidth",			XDR_CASE_MAX_SHIP_BANDWIDTH },
		{ "xdr-hotkey-time-ms",				XDR_CASE_HOTKEY_TIME_MS },
		{ "forward-xdr-writes",				XDR_CASE_FORWARD_XDR_WRITES },
		{ "xdr-client-threads",				XDR_CASE_CLIENT_THREADS },
		{ "xdr-write-timeout",				XDR_CASE_WRITE_TIMEOUT },
		{ "xdr-delete-shipping-enabled",	XDR_CASE_XDR_DELETE_SHIPPING_ENABLED },
		{ "xdr-ship-bins",					XDR_CASE_XDR_SHIP_BINS },
		{ "xdr-nsup-deletes-enabled",		XDR_CASE_XDR_NSUP_DELETES_ENABLED },
		{ "xdr-shipping-enabled",			XDR_CASE_XDR_SHIPPING_ENABLED },
		{ "xdr-info-timeout",				XDR_CASE_XDR_INFO_TIMEOUT },
		{ "xdr-compression-threshold",		XDR_CASE_XDR_COMPRESSION_THRESHOLD },
		{ "xdr-read-batch-size",			XDR_CASE_XDR_READ_BATCH_SIZE },				// deprecated (3.8.0)
		{ "xdr-ship-delay",					XDR_CASE_XDR_SHIP_DELAY },					// hidden
		{ "xdr-read-threads",				XDR_CASE_XDR_READ_THREADS},
		{ "}",								XDR_CASE_CONTEXT_END }
};

const xdr_cfg_opt XDR_DC_OPTS[] = {
		{ "{",								XDR_CASE_CONTEXT_BEGIN },
		{ "dc-node-address-port",			XDR_CASE_DC_NODE_ADDRESS_PORT },
		{ "dc-int-ext-ipmap",				XDR_CASE_DC_INT_EXT_IPMAP },
		{ "dc-security-config-file",		XDR_CASE_DC_SECURITY_CONFIG_FILE },
		{ "dc-use-alternate-services",		XDR_CASE_DC_USE_ALTERNATE_SERVICES },
		{ "}",								XDR_CASE_CONTEXT_END }
};

const int NUM_XDR_GLOBAL_OPTS		= sizeof(XDR_GLOBAL_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_NS_OPTS			= sizeof(XDR_NS_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_NS_STORAGE_OPTS	= sizeof(XDR_NS_STORAGE_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_NS_SET_OPTS		= sizeof(XDR_NS_SET_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_OPTS				= sizeof(XDR_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_DC_OPTS			= sizeof(XDR_DC_OPTS) / sizeof(xdr_cfg_opt);

// Security related configs
const xdr_cfg_opt XDR_SEC_GLOBAL_OPTS[] = {
		{ "credentials",					XDR_CASE_SEC_CREDENTIALS_BEGIN }
};

const xdr_cfg_opt XDR_SEC_CRED_OPTS[] = {
		{ "{",								XDR_CASE_CONTEXT_BEGIN },
		{ "username",						XDR_CASE_SEC_CRED_USERNAME },
		{ "password",						XDR_CASE_SEC_CRED_PASSWORD },
		{ "}",								XDR_CASE_CONTEXT_END }
};

const int NUM_XDR_SEC_GLOBAL_OPTS	= sizeof(XDR_SEC_GLOBAL_OPTS) / sizeof(xdr_cfg_opt);
const int NUM_XDR_SEC_CRED_OPTS		= sizeof(XDR_SEC_CRED_OPTS) / sizeof(xdr_cfg_opt);

// N.B.:  Default to false.
const bool g_xdr_supported;

void xdr_config_defaults(xdr_config *c)
{
	c->xdr_global_enabled = false;		// This config option overrides the enable-xdr setting of the namespace(s)

	c->xdr_digestlog_path = NULL;	// Path where the digest information is written to the disk
	c->xdr_digestlog_overwrite = true;
	c->xdr_digestlog_persist = true;
	c->xdr_info_port = 0;

	c->xdr_max_ship_throughput = 0;		// XDR TPS limit
	c->xdr_max_ship_bandwidth = 0;		// XDR bandwidth limit
	c->xdr_hotkey_time_ms = 100;		// Expiration time for the de-duplication cache
	c->xdr_read_threads = 4;			// Number of XDR read threads.
	c->xdr_write_timeout = 10000;		// Timeout for each element that is shipped.
	c->xdr_client_threads = 3;			// Number of async client threads (event loops)
	c->xdr_forward_xdrwrites = false;	// If the writes due to xdr should be forwarded
	c->xdr_nsup_deletes_enabled = false;// Shall XDR ship deletes of evictions or expiration
	c->xdr_internal_shipping_delay = 0;	// Default sleep between shipping each batch is 0 seconds
	c->xdr_conf_change_flag = 0;
	c->xdr_shipping_enabled = true;
	c->xdr_delete_shipping_enabled = true;
	c->xdr_ship_bins = false;
	c->xdr_info_request_timeout_ms = 10000;
	c->xdr_compression_threshold = 0; 	// 0 disables compressed shipping, > 0 specifies minimum request size for compression
	c->xdr_handle_failednode = true;
	c->xdr_handle_linkdown = true;
}
