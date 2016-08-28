/*
 * thr_info.c
 *
 * Copyright (C) 2008-2015 Aerospike, Inc.
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

#include "base/thr_info.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <malloc.h>
#include <mcheck.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "citrusleaf/cf_queue.h"
#include "citrusleaf/cf_shash.h"
#include "citrusleaf/cf_vector.h"

#include "xdr_config.h"

#include "cf_str.h"
#include "dynbuf.h"
#include "fault.h"
#include "jem.h"
#include "meminfo.h"
#include "socket.h"

#include "ai_obj.h"
#include "ai_btree.h"

#include "base/asm.h"
#include "base/batch.h"
#include "base/datamodel.h"
#include "base/ldt.h"
#include "base/monitor.h"
#include "base/scan.h"
#include "base/thr_batch.h"
#include "base/thr_sindex.h"
#include "base/thr_tsvc.h"
#include "base/transaction.h"
#include "base/xdr_serverside.h"
#include "base/secondary_index.h"
#include "base/security.h"
#include "base/stats.h"
#include "base/system_metadata.h"
#include "base/udf_cask.h"
#include "base/xdr_serverside.h"
#include "fabric/fabric.h"
#include "fabric/hb.h"
#include "fabric/hlc.h"
#include "fabric/migrate.h"
#include "fabric/paxos.h"
#include "transaction/proxy.h"
#include "transaction/rw_request_hash.h"

#define STR_NS              "ns"
#define STR_SET             "set"
#define STR_INDEXNAME       "indexname"
#define STR_NUMBIN          "numbins"
#define STR_INDEXDATA       "indexdata"
#define STR_TYPE_NUMERIC    "numeric"
#define STR_TYPE_STRING     "string"
#define STR_ITYPE           "indextype"
#define STR_ITYPE_DEFAULT   "DEFAULT"
#define STR_ITYPE_LIST      "LIST"
#define STR_ITYPE_MAPKEYS   "MAPKEYS"
#define STR_ITYPE_MAPVALUES "MAPVALUES"
#define STR_BINTYPE         "bintype"

extern int as_nsup_queue_get_size();

// Acceptable timediffs in XDR lastship times.
// (Print warning only if time went back by at least 5 minutes.)
#define XDR_ACCEPTABLE_TIMEDIFF XDR_TIME_ADJUST


int info_get_objects(char *name, cf_dyn_buf *db);
void clear_ldt_histograms();
int info_get_tree_sets(char *name, char *subtree, cf_dyn_buf *db);
int info_get_tree_bins(char *name, char *subtree, cf_dyn_buf *db);
int info_get_tree_sindexes(char *name, char *subtree, cf_dyn_buf *db);
void as_storage_show_wblock_stats(as_namespace *ns);
void as_storage_summarize_wblock_stats(as_namespace *ns);
int as_storage_analyze_wblock(as_namespace* ns, int device_index, uint32_t wblock_id);


//------------------------------------------------
// This is here for now, until such time as a
// separate .c file is worth it.
//

as_stats g_stats;

void
as_stats_init()
{
	memset((void*)&g_stats, 0, sizeof(g_stats));
}

//
// END - provisional stats.c
//------------------------------------------------

uint64_t g_start_ms; // start time of the server

static cf_queue *g_info_work_q = 0;

//
// Info has its own fabric service
// which allows it to communicate things like the IP addresses of
// all the other nodes
//

#define INFO_FIELD_OP	0
#define INFO_FIELD_GENERATION 1
#define INFO_FIELD_SERVICE_ADDRESS 2
#define INFO_FIELD_ALT_ADDRESS 3

#define INFO_OP_UPDATE 0
#define INFO_OP_ACK 1
#define INFO_OP_UPDATE_REQ 2

msg_template info_mt[] = {
	{ INFO_FIELD_OP,	M_FT_UINT32 },
	{ INFO_FIELD_GENERATION, M_FT_UINT32 },
	{ INFO_FIELD_SERVICE_ADDRESS, M_FT_STR },
	{ INFO_FIELD_ALT_ADDRESS, M_FT_STR }
};

#define INFO_MSG_SCRATCH_SIZE 128

// Is dumping GLibC-level memory stats enabled?
bool g_mstats_enabled = false;

// Is GLibC-level memory tracing enabled?
static bool g_mtrace_enabled = false;

// Default location for the memory tracing output:
#define DEFAULT_MTRACE_FILENAME  "/tmp/mtrace.out"

//
// The dynamic list has a name, and a function to call
//

typedef struct info_static_s {
	struct info_static_s	*next;
	bool   def; // default, but default is a reserved word
	char *name;
	char *value;
	size_t	value_sz;
} info_static;


typedef struct info_dynamic_s {
	struct info_dynamic_s *next;
	bool 	def;  // default, but that's a reserved word
	char *name;
	as_info_get_value_fn	value_fn;
} info_dynamic;

typedef struct info_command_s {
	struct info_command_s *next;
	char *name;
	as_info_command_fn 		command_fn;
	as_sec_perm				required_perm; // required security permission
} info_command;

typedef struct info_tree_s {
	struct info_tree_s *next;
	char *name;
	as_info_get_tree_fn	tree_fn;
} info_tree;


#define EOL		'\n' // incoming commands are separated by EOL
#define SEP		'\t'
#define TREE_SEP		'/'

#define INFO_COMMAND_SINDEX_FAILCODE(num, message)	\
	if (db) { \
		cf_dyn_buf_append_string(db, "FAIL:");			\
		cf_dyn_buf_append_int(db, num); 				\
		cf_dyn_buf_append_string(db, ":");				\
		cf_dyn_buf_append_string(db, message);          \
	}


void
info_get_aggregated_namespace_stats(cf_dyn_buf *db)
{
	uint64_t total_objects = 0;
	uint64_t total_sub_objects = 0;

	for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
		as_namespace *ns = g_config.namespaces[i];

		total_objects += ns->n_objects;
		total_sub_objects += ns->n_sub_objects;
	}

	info_append_uint64(db, "objects", total_objects);
	info_append_uint64(db, "sub_objects", total_sub_objects);
}

// #define INFO_SEGV_TEST 1
#ifdef INFO_SEGV_TEST
char *segv_test = "segv test";
int
info_segv_test(char *name, cf_dyn_buf *db)
{
	*segv_test = 'E';
	cf_dyn_buf_append_string(db, "segv");
	return(0);
}
#endif

int
info_get_stats(char *name, cf_dyn_buf *db)
{
	info_append_int(db, "cluster_size", g_paxos->cluster_size);
	info_append_uint64_x(db, "cluster_key", as_paxos_get_cluster_key()); // not in ticker
	info_append_bool(db, "cluster_integrity", as_paxos_get_cluster_integrity(g_paxos)); // not in ticker

	info_append_uint64(db, "uptime", (cf_getms() - g_start_ms) / 1000); // not in ticker

	int freepct;
	bool swapping;

	cf_meminfo(NULL, NULL, &freepct, &swapping);
	info_append_int(db, "system_free_mem_pct", freepct);
	info_append_bool(db, "system_swapping", swapping);

	info_get_aggregated_namespace_stats(db);

	info_append_int(db, "tsvc_queue", thr_tsvc_queue_get_size());
	info_append_int(db, "info_queue", as_info_queue_get_size());
	info_append_int(db, "delete_queue", as_nsup_queue_get_size());
	info_append_uint32(db, "rw_in_progress", rw_request_hash_count());
	info_append_uint32(db, "proxy_in_progress", as_proxy_hash_count());
	info_append_uint64(db, "record_refs", g_stats.global_record_ref_count);

	info_append_uint64(db, "client_connections", g_stats.proto_connections_opened - g_stats.proto_connections_closed);
	info_append_uint64(db, "heartbeat_connections", g_stats.heartbeat_connections_opened - g_stats.heartbeat_connections_closed);
	info_append_uint64(db, "fabric_connections", g_stats.fabric_connections_opened - g_stats.fabric_connections_closed);

	info_append_uint64(db, "heartbeat_received_self", g_stats.heartbeat_received_self);
	info_append_uint64(db, "heartbeat_received_foreign", g_stats.heartbeat_received_foreign);

	info_append_uint64(db, "reaped_fds", g_stats.reaper_count); // not in ticker

	info_append_uint64(db, "info_complete", g_stats.info_complete); // not in ticker

	info_append_uint64(db, "proxy_retry", g_stats.proxy_retry); // not in ticker

	info_append_uint64(db, "demarshal_error", g_stats.n_demarshal_error);
	info_append_uint64(db, "early_tsvc_client_error", g_stats.n_tsvc_client_error);
	info_append_uint64(db, "early_tsvc_batch_sub_error", g_stats.n_tsvc_batch_sub_error);
	info_append_uint64(db, "early_tsvc_udf_sub_error", g_stats.n_tsvc_udf_sub_error);

	info_append_uint64(db, "batch_index_initiate", g_stats.batch_index_initiate); // not in ticker

	cf_dyn_buf_append_string(db, "batch_index_queue=");
	as_batch_queues_info(db); // not in ticker
	cf_dyn_buf_append_char(db, ';');

	info_append_uint64(db, "batch_index_complete", g_stats.batch_index_complete);
	info_append_uint64(db, "batch_index_error", g_stats.batch_index_errors);
	info_append_uint64(db, "batch_index_timeout", g_stats.batch_index_timeout);

	// Everything below is not in ticker...

	info_append_int(db, "batch_index_unused_buffers", as_batch_unused_buffers());
	info_append_uint64(db, "batch_index_huge_buffers", g_stats.batch_index_huge_buffers);
	info_append_uint64(db, "batch_index_created_buffers", g_stats.batch_index_created_buffers);
	info_append_uint64(db, "batch_index_destroyed_buffers", g_stats.batch_index_destroyed_buffers);

	info_append_uint64(db, "batch_initiate", g_stats.batch_initiate);
	info_append_int(db, "batch_queue", as_batch_direct_queue_size());
	info_append_uint64(db, "batch_error", g_stats.batch_errors);
	info_append_uint64(db, "batch_timeout", g_stats.batch_timeout);

	info_append_int(db, "scans_active", as_scan_get_active_job_count());

	info_append_uint32(db, "query_short_running", g_query_short_running);
	info_append_uint32(db, "query_long_running", g_query_long_running);

	info_append_uint64(db, "sindex_ucgarbage_found", g_stats.query_false_positives);
	info_append_uint64(db, "sindex_gc_locktimedout", g_stats.sindex_gc_timedout);
	info_append_uint64(db, "sindex_gc_inactivity_dur", g_stats.sindex_gc_inactivity_dur);
	info_append_uint64(db, "sindex_gc_activity_dur", g_stats.sindex_gc_activity_dur);
	info_append_uint64(db, "sindex_gc_list_creation_time", g_stats.sindex_gc_list_creation_time);
	info_append_uint64(db, "sindex_gc_list_deletion_time", g_stats.sindex_gc_list_deletion_time);
	info_append_uint64(db, "sindex_gc_objects_validated", g_stats.sindex_gc_objects_validated);
	info_append_uint64(db, "sindex_gc_garbage_found", g_stats.sindex_gc_garbage_found);
	info_append_uint64(db, "sindex_gc_garbage_cleaned", g_stats.sindex_gc_garbage_cleaned);

	char paxos_principal[19];
	snprintf(paxos_principal, 19, "%"PRIX64"", as_paxos_succession_getprincipal());
	info_append_string(db, "paxos_principal", paxos_principal);

	info_append_bool(db, "migrate_allowed", as_partition_get_migration_flag());
	info_append_uint64(db, "migrate_partitions_remaining", as_partition_remaining_migrations());

	info_append_uint64(db, "fabric_msgs_sent", g_stats.fabric_msgs_sent);
	info_append_uint64(db, "fabric_msgs_rcvd", g_stats.fabric_msgs_rcvd);

	as_xdr_get_stats(name, db);

	cf_dyn_buf_chomp(db);

	return 0;
}

int
info_command_set_hb_protocol_v3(char* name, cf_dyn_buf* db)
{
	hb_protocol_enum protocol = AS_HB_PROTOCOL_V3;
	cf_info(AS_INFO, "Changing value of heartbeat protocol version to v3");
	if (0 > as_hb_set_protocol(protocol))
		cf_dyn_buf_append_string(db, "error");
	else
		cf_dyn_buf_append_string(db, "done");

	return 0;
}


cf_atomic32	 g_node_info_generation = 0;


int
info_get_cluster_generation(char *name, cf_dyn_buf *db)
{
	cf_dyn_buf_append_int(db, g_node_info_generation);

	return(0);
}

int
info_get_partition_generation(char *name, cf_dyn_buf *db)
{
	cf_dyn_buf_append_int(db, (int)g_partition_generation);

	return(0);
}

int
info_get_partition_info(char *name, cf_dyn_buf *db)
{
	as_partition_getinfo_str(db);

	return(0);
}

int
info_get_replicas_read(char *name, cf_dyn_buf *db)
{
	as_partition_getreplica_read_str(db);

	return(0);
}

int
info_get_replicas_prole(char *name, cf_dyn_buf *db)
{
	as_partition_getreplica_prole_str(db);

	return(0);
}

int
info_get_replicas_write(char *name, cf_dyn_buf *db)
{
	as_partition_getreplica_write_str(db);

	return(0);
}

int
info_get_replicas_master(char *name, cf_dyn_buf *db)
{
	as_partition_getreplica_master_str(db);

	return(0);
}

int
info_get_replicas_all(char *name, cf_dyn_buf *db)
{
	as_partition_get_replicas_all_str(db);

	return(0);
}

//
// COMMANDS
//

int
info_command_get_sl(char *name, char *params, cf_dyn_buf *db)
{
	char *result = "error";

	//  Get the Paxos Succession List:
	// Command Format:  "get-sl:"

	if (!as_paxos_get_succession_list(db)) {
		result = "ok";
	}

	cf_dyn_buf_append_string(db, result);

	return 0;
}

int
info_command_tip(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "tip command received: params %s", params);

	char host_str[50];
	int  host_str_len = sizeof(host_str);

	char port_str[50];
	int  port_str_len = sizeof(port_str);

	/*
	 *  Command Format:  "tip:host=<IPAddr>;port=<PortNum>"
	 *
	 *  where <IPAddr> is an IP address and <PortNum> is a valid TCP port number.
	 */

	if (0 != as_info_parameter_get(params, "host", host_str, &host_str_len)) {
		cf_warning(AS_INFO, "tip command: no host, must add a host parameter");
		return(0);
	}

	if (0 != as_info_parameter_get(params, "port", port_str, &port_str_len)) {
		cf_warning(AS_INFO, "tip command: no port, must have port");
		return(0);
	}

	int port = 0;
	if (0 != cf_str_atoi(port_str, &port)) {
		cf_warning(AS_INFO, "tip command: port must be an integer in: %s", port_str);
		return(0);
	}

	int rv = as_hb_mesh_tip(host_str, port);

	switch (rv) {
		case SHASH_OK:
			cf_info(AS_INFO, "tip command executed: params %s",
				params);
			cf_dyn_buf_append_string(db, "ok");
			break;
		case SHASH_ERR_FOUND:
			cf_warning(AS_INFO, "tip command failed: params %s",
				params);
			cf_dyn_buf_append_string(db, "error: already exists");
			break;
		case SHASH_ERR:
			cf_warning(AS_INFO, "tip command failed: params %s",
				params);
			cf_dyn_buf_append_string(db, "error");
			break;
	}

	return(0);
}

/*
 *  Command Format:  "tip-clear:{host-port-list=<hpl>}" [the "host-port-list" argument is optional]
 *
 *  where <hpl> is either "all" or else a comma-separated list of items of the form: <HostIPAddr>:<PortNum>
 */
int32_t
info_command_tip_clear(char* name, char* params, cf_dyn_buf* db)
{
	cf_info(AS_INFO, "tip clear command received: params %s", params);

	// Command Format:  "tip-clear:{host-port-list=<hpl>}" [the
	// "host-port-list" argument is optional]
	// where <hpl> is either "all" or else a comma-separated list of items
	// of the form: <HostIPAddr>:<PortNum>

	char host_port_list[3000];
	int host_port_list_len = sizeof(host_port_list);
	host_port_list[0] = '\0';
	bool clear_all = false, success = true;
	int cleared = 0;

	if (as_info_parameter_get(params, "host-port-list", host_port_list,
				  &host_port_list_len) == 0) {
		if (0 != strcmp(host_port_list, "all")) {
			char* save_ptr = NULL;
			int port = -1;
			char* host_port =
			  strtok_r(host_port_list, ",", &save_ptr);

			while (host_port != NULL) {
				char* host_port_save_ptr = NULL;
				char* host =
				  strtok_r(host_port, ":", &host_port_save_ptr);

				if (host == NULL) {
					cf_warning(AS_INFO,
						   "tip clear command: invalid host:port string: %s",
						   host_port);
					return (0);
				}

				char* port_str =
				  strtok_r(NULL, ":", &host_port_save_ptr);
				if (port_str == NULL ||
				    0 != cf_str_atoi(port_str, &port)) {
					cf_warning(AS_INFO,
						   "tip clear command: port must be an integer in: %s",
						   port_str);
					return (0);
				}

				if (as_hb_mesh_tip_clear(host, port) == -1) {
					success = false;
					break;
				}
				cleared++;
				host_port = strtok_r(NULL, ",", &save_ptr);
			}
		} else {
			clear_all = true;
			if (as_hb_mesh_tip_clear_all()) {
				success = false;
			}
		}
	} else {
		success = false;
	}

	if (success) {
		char cleared_s[8];
		cf_str_itoa(cleared, cleared_s, 10);
		cf_info(AS_INFO,
			"tip clear command executed: cleared %s, params %s",
			(clear_all ? "all" : cleared_s), params);
		cf_dyn_buf_append_string(db, "ok");
	} else {
		cf_info(
		  AS_INFO, "tip clear %s command failed: cleared %d, params %s",
		  (clear_all ? "all" : ""), (clear_all ? 0 : cleared), params);
		cf_dyn_buf_append_string(db, "error");
	}

	return (0);
}

int
info_command_show_devices(char *name, char *params, cf_dyn_buf *db)
{
	char ns_str[512];
	int  ns_len = sizeof(ns_str);

	if (0 != as_info_parameter_get(params, "namespace", ns_str, &ns_len)) {
		cf_info(AS_INFO, "show-devices requires namespace parameter");
		cf_dyn_buf_append_string(db, "error");
		return(0);
	}

	as_namespace *ns = as_namespace_get_byname(ns_str);
	if (!ns) {
		cf_info(AS_INFO, "show-devices: namespace %s not found", ns_str);
		cf_dyn_buf_append_string(db, "error");
		return(0);
	}
	as_storage_show_wblock_stats(ns);

	cf_dyn_buf_append_string(db, "ok");

	return(0);
}

int
info_command_dump_fabric(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-fabric:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	as_fabric_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_dump_hb(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-hb:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	as_hb_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_dump_hlc(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-hlc:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	as_hlc_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}


int
info_command_dump_migrates(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-migrates:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	as_migrate_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_dump_msgs(char *name, char *params, cf_dyn_buf *db)
{
	bool once = true;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-msgs:{mode=<mode>}" [the "mode" argument is optional]
	 *
	 *   where <mode> is one of:  {"on" | "off" | "once"} and defaults to "once".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "mode", param_str, &param_str_len)) {
		if (!strncmp(param_str, "on", 3)) {
			g_config.fabric_dump_msgs = true;
		} else if (!strncmp(param_str, "off", 4)) {
			g_config.fabric_dump_msgs = false;
			once = false;
		} else if (!strncmp(param_str, "once", 5)) {
			once = true;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"mode\" value must be one of {\"on\", \"off\", \"once\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	if (once) {
		as_fabric_msg_queue_dump();
	}

	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

static int
is_numeric_string(char *str)
{
	if (!*str)
		return 0;

	while (isdigit(*str))
		str++;

	return (!*str);
}

int
info_command_dump_wb(char *name, char *params, cf_dyn_buf *db)
{
	as_namespace *ns;
	int device_index, wblock_id;
	char param_str[100];
	int param_str_len;

	/*
	 *  Command Format:  "dump-wb:ns=<Namespace>;dev=<DeviceID>;id=<WBlockId>"
	 *
	 *   where <Namespace> is the name of the namespace,
	 *         <DeviceID> is the drive number (a non-negative integer), and
	 *         <WBlockID> is a non-negative integer corresponding to an active wblock.
	 */
	param_str[0] = '\0';
	param_str_len = sizeof(param_str);
	if (!as_info_parameter_get(params, "ns", param_str, &param_str_len)) {
		if (!(ns = as_namespace_get_byname(param_str))) {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"ns\" value must be the name of an existing namespace, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires an argument of the form \"ns=<Namespace>\"", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	param_str[0] = '\0';
	param_str_len = sizeof(param_str);
	if (!as_info_parameter_get(params, "dev", param_str, &param_str_len)) {
		if (!is_numeric_string(param_str) || (0 > (device_index = atoi(param_str)))) {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"dev\" value must be a non-negative integer, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires an argument of the form \"dev=<DeviceID>\"", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	param_str[0] = '\0';
	param_str_len = sizeof(param_str);
	if (!as_info_parameter_get(params, "id", param_str, &param_str_len)) {
		if (!is_numeric_string(param_str) || (0 > (wblock_id = atoi(param_str)))) {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"id\" value must be a non-negative integer, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires an argument of the form \"id=<WBlockID>\"", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	if (!as_storage_analyze_wblock(ns, device_index, (uint32_t) wblock_id))
		cf_dyn_buf_append_string(db, "ok");
	else
		cf_dyn_buf_append_string(db, "error");

	return(0);
}

int
info_command_dump_wb_summary(char *name, char *params, cf_dyn_buf *db)
{
	as_namespace *ns;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-wb-summary:ns=<Namespace>"
	 *
	 *  where <Namespace> is the name of an existing namespace.
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "ns", param_str, &param_str_len)) {
		if (!(ns = as_namespace_get_byname(param_str))) {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"ns\" value must be the name of an existing namespace, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return(0);
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires an argument of the form \"ns=<Namespace>\"", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	as_storage_summarize_wblock_stats(ns);

	cf_dyn_buf_append_string(db, "ok");

	return(0);
}

int
info_command_dump_rw_request_hash(char *name, char *params, cf_dyn_buf *db)
{
	rw_request_hash_dump();
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_dump_paxos(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-paxos:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	as_paxos_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_dump_ra(char *name, char *params, cf_dyn_buf *db)
{
	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-ra:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}
	cc_cluster_config_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");
	return(0);
}

int
info_command_alloc_info(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "alloc-info command received: params %s", params);

#ifdef MEM_COUNT
	/*
	 *  Command Format:  "alloc-info:loc=<loc>"
	 *
	 *   where <loc> is a string of the form:  <Filename>:<LineNumber>
	 */

	char param_str[100], file[100];
	int line;
	int param_str_len = sizeof(param_str);

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "loc", param_str, &param_str_len)) {
		char *colon_ptr = strchr(param_str, ':');
		if (colon_ptr) {
			*colon_ptr++ = '\0';
			strncpy(file, param_str, sizeof(file));
			line = atoi(colon_ptr);
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command \"loc\" parameter (received: \"%s\") needs to be of the form: <Filename>:<LineNumber>", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires a \"loc\" parameter of the form: <Filename>:<LineNumber>", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	char *status = "ok";
	if (mem_count_alloc_info(file, line, db)) {
		status = "error";
	}
	cf_dyn_buf_append_string(db, status);
#else
	cf_warning(AS_INFO, "memory allocation counting not compiled into build ~~ rebuild with \"MEM_COUNT=1\" to use");
	cf_dyn_buf_append_string(db, "error");
#endif

	return 0;
}

int
info_command_mem(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "mem command received: params %s", params);

#ifdef MEM_COUNT
	/*
	 *	Command Format:	 "mem:{top_n=<N>;sort_by=<opt>}"
	 *
	 *	 where <opt> is one of:
	 *      "space"         --  Net allocation size.
	 *      "time"          --  Most recently allocated.
	 *      "net_count"     --  Net number of allocation calls.
	 *      "total_count"   --  Total number of allocation calls.
	 *      "change"        --  Delta in allocation size.
	 */

	// These next values are the initial defaults for the report to be run.
	static int top_n = 10;
	static sort_field_t sort_by = CF_ALLOC_SORT_NET_SZ;

	char param_str[100];
	int param_str_len = sizeof(param_str);

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "top_n", param_str, &param_str_len)) {
		int new_top_n = atoi(param_str);
		if ((new_top_n >= 1) && (new_top_n <= 100000)) {
			top_n = new_top_n;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command \"top_n\" value (received: %d) must be >= 1 and <= 100000.", name, new_top_n);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	param_str_len = sizeof(param_str);
	if (!as_info_parameter_get(params, "sort_by", param_str, &param_str_len)) {
		if (!strcmp(param_str, "space")) {
			sort_by = CF_ALLOC_SORT_NET_SZ;
		} else if (!strcmp(param_str, "time")) {
			sort_by = CF_ALLOC_SORT_TIME_LAST_MODIFIED;
		} else if (!strcmp(param_str, "net_count")) {
			sort_by = CF_ALLOC_SORT_NET_ALLOC_COUNT;
		} else if (!strcmp(param_str, "total_count")) {
			sort_by = CF_ALLOC_SORT_TOTAL_ALLOC_COUNT;
		} else if (!strcmp(param_str, "change")) {
			sort_by = CF_ALLOC_SORT_DELTA_SZ;
		} else {
			cf_warning(AS_INFO, "Unknown \"%s:\" command \"sort_by\" option (received: \"%s\".)  Must be one of: {\"space\", \"time\", \"net_count\", \"total_count\", \"change\"}.", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	char *status = "ok";
	if (mem_count_report(sort_by, top_n, db)) {
		status = "error";
	}
	cf_dyn_buf_append_string(db, status);
#else
	cf_warning(AS_INFO, "memory allocation counting not compiled into build ~~ rebuild with \"MEM_COUNT=1\" to use");
	cf_dyn_buf_append_string(db, "error");
#endif

	return 0;
}

void
info_log_with_datestamp(void (*log_fn)(void))
{
	char datestamp[1024];
	struct tm nowtm;
	time_t now = time(NULL);
	gmtime_r(&now, &nowtm);
	strftime(datestamp, sizeof(datestamp), "%b %d %Y %T %Z:\n", &nowtm);

	/* Output the date-stamp followed by the output of the log function. */
	fprintf(stderr, "%s", datestamp);
	log_fn();
	fprintf(stderr, "\n");
}

int
info_command_mstats(char *name, char *params, cf_dyn_buf *db)
{
	bool enable = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	cf_debug(AS_INFO, "mstats command received: params %s", params);

	/*
	 *  Command Format:  "mstats:{enable=<opt>}" [the "enable" argument is optional]
	 *
	 *   where <opt> is one of:  {"true" | "false"} and by default dumps the memory stats once.
	 */

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "enable", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 3)) {
			enable = true;
		} else if (!strncmp(param_str, "false", 4)) {
			enable = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"enable\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}

		if (g_mstats_enabled && !enable) {
			cf_info(AS_INFO, "mstats:  memory stats disabled");
			g_mstats_enabled = enable;
		} else if (!g_mstats_enabled && enable) {
			cf_info(AS_INFO, "mstats:  memory stats enabled");
			g_mstats_enabled = enable;
		}
	} else {
		// No parameter supplied -- Just do it once and don't change the enabled state.
		info_log_with_datestamp(malloc_stats);
	}

	cf_dyn_buf_append_string(db, "ok");

	return 0;
}

int
info_command_mtrace(char *name, char *params, cf_dyn_buf *db)
{
	bool enable = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	cf_debug(AS_INFO, "mtrace command received: params %s", params);

	/*
	 *  Command Format:  "mtrace:{enable=<opt>}" [the "enable" argument is optional]
	 *
	 *   where <opt> is one of:  {"true" | "false"} and by default toggles the current state.
	 */

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "enable", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 3)) {
			enable = true;
		} else if (!strncmp(param_str, "false", 4)) {
			enable = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"enable\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		enable = !g_mtrace_enabled;
	}

	// Use the default mtrace output file if not already set in the environment.
	setenv("MALLOC_TRACE", DEFAULT_MTRACE_FILENAME, false);
	cf_debug(AS_INFO, "mtrace:  MALLOC_TRACE = \"%s\"", getenv("MALLOC_TRACE"));

	if (g_mtrace_enabled && !enable) {
		cf_info(AS_INFO, "mtrace:  memory tracing disabled");
		muntrace();
		g_mtrace_enabled = enable;
	} else if (!g_mtrace_enabled && enable) {
		cf_info(AS_INFO, "mtrace:  memory tracing enabled");
		mtrace();
		g_mtrace_enabled = enable;
	}

	cf_dyn_buf_append_string(db, "ok");

	return 0;
}

int
info_command_jem_stats(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "jem_stats command received: params %s", params);

#ifdef USE_JEM
	/*
	 *	Command Format:	 "jem-stats:"
	 *
	 *  Logs the JEMalloc statistics to the console.
	 */
	info_log_with_datestamp(jem_log_stats);
	cf_dyn_buf_append_string(db, "ok");
#else
	cf_warning(AS_INFO, "JEMalloc interface not compiled into build ~~ rebuild with \"USE_JEM=1\" to use");
	cf_dyn_buf_append_string(db, "error");
#endif

	return 0;
}

int
info_command_double_free(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "df command received: params %s", params);

#ifdef USE_DF_DETECT
	/*
	 *  Purpose:         Do an intentional double "free()" to test Double "free()" Detection.
	 *
	 *  Command Format:  "df:"
	 *
	 *  This command operates in a 3-cycle to trigger a double "free()" condition:
	 *
	 *  - Executing this command the first time will dynamically allocate a small block of memory.
	 *
	 *  - Executing this command the second time will free the block.
	 *
	 *  - Executing it a third time will actually perform the double "free()" and should trigger
	 *       the double "free()" detector, which will log an informative warning message.
	 *
	 *  - Executing it thereafter will repeat the 3-cycle, albeit using a different pseudo-random block size.
	 *
	 *  ***Warning***:  This command is provided *only* for testing abnormal situations.
	 *                  Do not use it unless you are prepared for the potential consequences!
	 */

	static size_t block_sz = 1024, incr = 255, max = 2048;
	static char *ptr = 0;
	static int ctr = 0;

	if (!ptr) {
		cf_dyn_buf_append_string(db, "calling cf_""malloc(");
		cf_dyn_buf_append_int(db, block_sz);
		cf_dyn_buf_append_string(db, ")");
		ptr = cf_malloc(block_sz);
	} else {
		cf_dyn_buf_append_string(db, "calling cf_""free(0x");
		cf_dyn_buf_append_uint64_x(db, (uint64_t) ptr);
		cf_dyn_buf_append_string(db, ")");
		cf_free(ptr);
		if (ctr++) {
			ctr = 0;
			ptr = 0;
			block_sz = (block_sz + incr) % max;
		}
	}
#else
	cf_warning(AS_INFO, "Double \"free()\" Detection support is not compiled into build ~~ rebuild with \"USE_DF_DETECT=1\" to use");
	cf_dyn_buf_append_string(db, "error");
#endif

	return 0;
}

int
info_command_asm(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "asm command received: params %s", params);

#ifdef USE_ASM
	/*
	 *  Purpose:         Control the operation of the ASMalloc library.
	 *
	 *	Command Format:	 "asm:{enable=<opt>;<thresh>=<int>;features=<feat>;stats}"
	 *
	 *   where <opt> is one of:  {"true" | "false"},
	 *
	 *   and <thresh> is one of:
	 *
	 *      "block_size"     --  Minimum block size in bytes to trigger a mallocation alerts.
	 *      "delta_size"     --  Minimum size change in bytes between mallocation alerts per thread.
	 *      "delta_time"     --  Minimum time in seconds between mallocation alerts per thread.
	 *
	 *   and <int> is the new integer value for the given threshold (-1 means infinite.)
	 *
	 *   and <feat> is a hexadecimal value representing a bit vector of ASMalloc features to enable.
	 *
	 *   One or more of: {"enable" | <thresh> | "features"} may be supplied.
	 */

	bool enable_cmd = false, thresh_cmd = false, features_cmd = false, stats_cmd = false;

	bool enable = false;
	uint64_t value = 0;
	uint64_t features = 0;

	char param_str[100];
	int param_str_len = sizeof(param_str);

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "enable", param_str, &param_str_len)) {
		enable_cmd = true;

		if (!strncmp(param_str, "true", 3)) {
			enable = true;
		} else if (!strncmp(param_str, "false", 4)) {
			enable = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"enable\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "block_size", param_str, &param_str_len)) {
		thresh_cmd = true;

		if (!strcmp(param_str, "-1")) {
			value = UINT64_MAX;
		} else {
			cf_str_atoi_u64_x(param_str, &value, 10);
		}

		g_thresh_block_size = value;
	}

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "delta_size", param_str, &param_str_len)) {
		thresh_cmd = true;

		if (!strcmp(param_str, "-1")) {
			value = UINT64_MAX;
		} else {
			cf_str_atoi_u64_x(param_str, &value, 10);
		}

		g_thresh_delta_size = value;
	}

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "delta_time", param_str, &param_str_len)) {
		thresh_cmd = true;

		if (!strcmp(param_str, "-1")) {
			value = UINT64_MAX;
		} else {
			cf_str_atoi_u64_x(param_str, &value, 10);
		}

		g_thresh_delta_time = value;
	}

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "features", param_str, &param_str_len)) {
		features_cmd = true;
		cf_str_atoi_u64_x(param_str, &features, 16);
	}

	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "stats", param_str, &param_str_len)) {
		stats_cmd = true;
		as_asm_cmd(ASM_CMD_PRINT_STATS);
	}

	// If we made it this far, actually perform the requested action(s).

	if (enable_cmd) {
		cf_info(AS_INFO, "asm: setting enable = %s ", (enable ? "true" : "false"));

		g_config.asmalloc_enabled = g_asm_hook_enabled = enable;

		if (enable != g_asm_cb_enabled) {
			g_asm_cb_enabled = enable;
			as_asm_cmd(ASM_CMD_SET_CALLBACK, (enable ? my_cb : NULL), (enable ? g_my_cb_udata : NULL));
		}
	}

	if (thresh_cmd) {
		cf_info(AS_INFO, "asm: setting thresholds: block_size = %lu ; delta_size = %lu ; delta_time = %lu",
				g_thresh_block_size, g_thresh_delta_size, g_thresh_delta_time);
		as_asm_cmd(ASM_CMD_SET_THRESHOLDS, g_thresh_block_size, g_thresh_delta_size, g_thresh_delta_time);
	}

	if (features_cmd) {
		cf_info(AS_INFO, "asm: setting features = 0x%lx ", features);
		as_asm_cmd(ASM_CMD_SET_FEATURES, features);
	}

	if (!(enable_cmd || thresh_cmd || features_cmd || stats_cmd)) {
		cf_warning(AS_INFO, "The \"%s:\" command must contain at least one of {\"enable\", \"features\", \"block_size\", \"delta_size\", \"delta_time\", \"stats\"}, not \"%s\"", name, params);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	cf_dyn_buf_append_string(db, "ok");
#else
	cf_warning(AS_INFO, "ASMalloc support is not compiled into build ~~ rebuild with \"USE_ASM=1\" to use");
	cf_dyn_buf_append_string(db, "error");
#endif // defined(USE_ASM)

	return 0;
}

/*
 *  Print out System Metadata info.
 */
int
info_command_dump_smd(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "dump-smd command received: params %s", params);

	bool verbose = false;
	char param_str[100];
	int param_str_len = sizeof(param_str);

	/*
	 *  Command Format:  "dump-smd:{verbose=<opt>}" [the "verbose" argument is optional]
	 *
	 *  where <opt> is one of:  {"true" | "false"} and defaults to "false".
	 */
	param_str[0] = '\0';
	if (!as_info_parameter_get(params, "verbose", param_str, &param_str_len)) {
		if (!strncmp(param_str, "true", 5)) {
			verbose = true;
		} else if (!strncmp(param_str, "false", 6)) {
			verbose = false;
		} else {
			cf_warning(AS_INFO, "The \"%s:\" command argument \"verbose\" value must be one of {\"true\", \"false\"}, not \"%s\"", name, param_str);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	as_smd_dump(verbose);
	cf_dyn_buf_append_string(db, "ok");

	return 0;
}

/*
 *  Manipulate System Metatdata.
 */
int
info_command_smd_cmd(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "smd command received: params %s", params);

	/*
	 *	Command Format:	 "smd:cmd=<cmd>;module=<string>{node=<hexadecimal string>;key=<string>;value=<hexadecimal string>}"
	 *
	 *	 where <cmd> is one of:
	 *      "create"       --  Create a new container for the given module's metadata.
	 *      "destroy"      --  Destroy the container for the given module's metadata after deleting all the metadata within it.
	 *      "set"          --  Add a new, or modify an existing, item of metadata in a given module.
	 *      "delete"       --  Delete an existing item of metadata from a given module.
	 *      "get"          --  Look up the given key in the given module's metadata.
	 *      "init"         --  (Re-)Initialize the System Metadata module.
	 *      "start"        --  Start up the System Metadata module for receiving Paxos state change events.
	 *      "shutdown"     --  Terminate the System Metadata module.
	 */

	char cmd[10], module[256], node[17], key[256], value[1024];
	int cmd_len = sizeof(cmd);
	int module_len = sizeof(module);
	int node_len = sizeof(node);
	int key_len = sizeof(key);
	int value_len = sizeof(value);
	cf_node node_id = 0;

	cmd[0] = '\0';
	if (!as_info_parameter_get(params, "cmd", cmd, &cmd_len)) {
		if (strcmp(cmd, "create") && strcmp(cmd, "destroy") && strcmp(cmd, "set") && strcmp(cmd, "delete") && strcmp(cmd, "get") &&
				strcmp(cmd, "init") && strcmp(cmd, "start") && strcmp(cmd, "shutdown")) {
			cf_warning(AS_INFO, "Unknown \"%s:\" command \"cmd\" cmdtion (received: \"%s\".)  Must be one of: {\"create\", \"destroy\", \"set\", \"delete\", \"get\", \"init\", \"start\", \"shutdown\"}.", name, cmd);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	} else {
		cf_warning(AS_INFO, "The \"%s:\" command requires an \"cmd\" parameter", name);
		cf_dyn_buf_append_string(db, "error");
		return 0;
	}

	module[0] = '\0';
	if (strcmp(cmd, "init") && strcmp(cmd, "start") && strcmp(cmd, "shutdown")) {
		if (as_info_parameter_get(params, "module", module, &module_len)) {
			cf_warning(AS_INFO, "The \"%s:\" command requires a \"module\" parameter", name);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	if (!strcmp(cmd, "get")) {
		node[0] = '\0';
		if (!as_info_parameter_get(params, "node", node, &node_len)) {
			if (cf_str_atoi_u64_x(node, &node_id, 16)) {
				cf_warning(AS_INFO, "The \"%s:\" command \"node\" parameter must be a 64-bit hex number, not \"%s\"", name, node);
				cf_dyn_buf_append_string(db, "error");
				return 0;
			}
		}
	}

	if (!strcmp(cmd, "set") || !strcmp(cmd, "delete") || !strcmp(cmd, "get")) {
		key[0] = '\0';
		if (as_info_parameter_get(params, "key", key, &key_len)) {
			cf_warning(AS_INFO, "The \"%s:\" command \"%s\" requires a \"key\" parameter", name, cmd);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	if (!strcmp(cmd, "set")) {
		value[0] = '\0';
		if (as_info_parameter_get(params, "value", value, &value_len)) {
			cf_warning(AS_INFO, "The \"%s:\" command \"%s\" requires a \"value\" parameter", name, cmd);
			cf_dyn_buf_append_string(db, "error");
			return 0;
		}
	}

	as_smd_info_cmd(cmd, node_id, module, key, value);
	cf_dyn_buf_append_string(db, "ok");

	return 0;
}

int
info_command_mon_cmd(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "add-module command received: params %s", params);

	/*
	 *  Command Format:  "jobs:[module=<string>;cmd=<command>;<parameters>]"
	 *                   asinfo -v 'jobs'              -> list all jobs
	 *                   asinfo -v 'jobs:module=query' -> list all jobs for query module
	 *                   asinfo -v 'jobs:module=query;cmd=kill-job;trid=<trid>'
	 *                   asinfo -v 'jobs:module=query;cmd=set-priority;trid=<trid>;value=<val>'
	 *
	 *  where <module> is one of following:
	 *      - query
	 *      - scan
	 */

	char cmd[13];
	char module[21];
	char job_id[24];
	char val_str[11];
	int cmd_len       = sizeof(cmd);
	int module_len    = sizeof(module);
	int job_id_len    = sizeof(job_id);
	int val_len       = sizeof(val_str);
	uint64_t trid     = 0;
	uint32_t value    = 0;

	cmd[0]     = '\0';
	module[0]  = '\0';
	job_id[0]  = '\0';
	val_str[0] = '\0';

	// Read the parameters: module cmd trid value
	int rv = as_info_parameter_get(params, "module", module, &module_len);
	if (rv == -1) {
		as_mon_info_cmd(NULL, NULL, 0, 0, db);
		return 0;
	}
	else if (rv == -2) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_PARAMETER);
		cf_dyn_buf_append_string(db, ":\"module\" parameter too long (> ");
		cf_dyn_buf_append_int(db, module_len-1);
		cf_dyn_buf_append_string(db, " chars)");
		return 0;
	}

	rv = as_info_parameter_get(params, "cmd", cmd, &cmd_len);
	if (rv == -1) {
		as_mon_info_cmd(module, NULL, 0, 0, db);
		return 0;
	}
	else if (rv == -2) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_PARAMETER);
		cf_dyn_buf_append_string(db, ":\"cmd\" parameter too long (> ");
		cf_dyn_buf_append_int(db, cmd_len-1);
		cf_dyn_buf_append_string(db, " chars)");
		return 0;
	}

	rv = as_info_parameter_get(params, "trid", job_id, &job_id_len);
	if (rv == 0) {
		trid  = strtoull(job_id, NULL, 10);
	}
	else if (rv == -1) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_PARAMETER);
		cf_dyn_buf_append_string(db, ":no \"trid\" parameter specified");
		return 0;
	}
	else if (rv == -2) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_PARAMETER);
		cf_dyn_buf_append_string(db, ":\"trid\" parameter too long (> ");
		cf_dyn_buf_append_int(db, job_id_len-1);
		cf_dyn_buf_append_string(db, " chars)");
		return 0;
	}

	rv = as_info_parameter_get(params, "value", val_str, &val_len);
	if (rv == 0) {
		value = strtoul(val_str, NULL, 10);
	}
	else if (rv == -2) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_PARAMETER);
		cf_dyn_buf_append_string(db, ":\"value\" parameter too long (> ");
		cf_dyn_buf_append_int(db, val_len-1);
		cf_dyn_buf_append_string(db, " chars)");
		return 0;
	}

	cf_info(AS_INFO, "%s %s %lu %u", module, cmd, trid, value);
	as_mon_info_cmd(module, cmd, trid, value, db);
	return 0;
}



void
info_service_config_get(cf_dyn_buf *db)
{
	// Note - no user, group.
	info_append_uint32(db, "paxos-single-replica-limit", g_config.paxos_single_replica_limit);
	info_append_string(db, "pidfile", g_config.pidfile ? g_config.pidfile : "null");
	info_append_int(db, "service-threads", g_config.n_service_threads);
	info_append_int(db, "transaction-queues", g_config.n_transaction_queues);
	info_append_int(db, "transaction-threads-per-queue", g_config.n_transaction_threads_per_queue);
	info_append_int(db, "proto-fd-max", g_config.n_proto_fd_max);

	info_append_bool(db, "allow-inline-transactions", g_config.allow_inline_transactions);
	info_append_int(db, "batch-threads", g_config.n_batch_threads);
	info_append_uint32(db, "batch-max-buffers-per-queue", g_config.batch_max_buffers_per_queue);
	info_append_uint32(db, "batch-max-requests", g_config.batch_max_requests);
	info_append_uint32(db, "batch-max-unused-buffers", g_config.batch_max_unused_buffers);
	info_append_uint32(db, "batch-priority", g_config.batch_priority);
	info_append_int(db, "batch-index-threads", g_config.n_batch_index_threads);
	info_append_int(db, "clock-skew-max-ms", g_config.clock_skew_max_ms);

	char cluster_id[AS_CLUSTER_ID_SZ];
	as_config_cluster_id_get(cluster_id);
	if (cluster_id[0]) {
		// TODO: print none in v3.
		info_append_string(db, "cluster-id", cluster_id);
	}

	info_append_bool(db, "enable-benchmarks-svc", g_config.svc_benchmarks_enabled);
	info_append_bool(db, "enable-hist-info", g_config.info_hist_enabled);
	info_append_int(db, "fabric-workers", g_config.n_fabric_workers);
	info_append_bool(db, "generation-disable", g_config.generation_disable);
	info_append_uint32(db, "hist-track-back", g_config.hist_track_back);
	info_append_uint32(db, "hist-track-slice", g_config.hist_track_slice);
	info_append_string(db, "hist-track-thresholds", g_config.hist_track_thresholds ? g_config.hist_track_thresholds : "null");
	info_append_int(db, "info-threads", g_config.n_info_threads);
	info_append_bool(db, "ldt-benchmarks", g_config.ldt_benchmarks);
	info_append_bool(db, "log-local-time", cf_fault_is_using_local_time());
	info_append_int(db, "migrate-max-num-incoming", g_config.migrate_max_num_incoming);
	info_append_int(db, "migrate-rx-lifetime-ms", g_config.migrate_rx_lifetime_ms);
	info_append_int(db, "migrate-threads", g_config.n_migrate_threads);
	info_append_uint32(db, "nsup-delete-sleep", g_config.nsup_delete_sleep);
	info_append_uint32(db, "nsup-period", g_config.nsup_period);
	info_append_bool(db, "nsup-startup-evict", g_config.nsup_startup_evict);
	info_append_uint64(db, "paxos-max-cluster-size", g_config.paxos_max_cluster_size);

	info_append_string(db, "paxos-protocol",
			(AS_PAXOS_PROTOCOL_V1 == g_config.paxos_protocol ? "v1" :
				(AS_PAXOS_PROTOCOL_V2 == g_config.paxos_protocol ? "v2" :
					(AS_PAXOS_PROTOCOL_V3 == g_config.paxos_protocol ? "v3" :
						(AS_PAXOS_PROTOCOL_V4 == g_config.paxos_protocol ? "v4" :
							(AS_PAXOS_PROTOCOL_NONE == g_config.paxos_protocol ? "none" : "undefined"))))));

	info_append_string(db, "paxos-recovery-policy",
			(AS_PAXOS_RECOVERY_POLICY_AUTO_RESET_MASTER == g_config.paxos_recovery_policy ? "auto-reset-master" : "undefined"));

	info_append_uint32(db, "paxos-retransmit-period", g_config.paxos_retransmit_period);
	info_append_int(db, "proto-fd-idle-ms", g_config.proto_fd_idle_ms);
	info_append_int(db, "proto-slow-netio-sleep-ms", g_config.proto_slow_netio_sleep_ms); // dynamic only
	info_append_uint32(db, "query-batch-size", g_config.query_bsize);
	info_append_uint32(db, "query-buf-size", g_config.query_buf_size); // dynamic only
	info_append_uint32(db, "query-bufpool-size", g_config.query_bufpool_size);
	info_append_bool(db, "query-in-transaction-thread", g_config.query_in_transaction_thr);
	info_append_uint32(db, "query-long-q-max-size", g_config.query_long_q_max_size);
	info_append_bool(db, "query-microbenchmark", g_config.query_enable_histogram); // dynamic only
	info_append_bool(db, "query-pre-reserve-partitions", g_config.partitions_pre_reserved);
	info_append_uint32(db, "query-priority", g_config.query_priority);
	info_append_uint64(db, "query-priority-sleep-us", g_config.query_sleep_us);
	info_append_uint64(db, "query-rec-count-bound", g_config.query_rec_count_bound);
	info_append_bool(db, "query-req-in-query-thread", g_config.query_req_in_query_thread);
	info_append_uint32(db, "query-req-max-inflight", g_config.query_req_max_inflight);
	info_append_uint32(db, "query-short-q-max-size", g_config.query_short_q_max_size);
	info_append_uint32(db, "query-threads", g_config.query_threads);
	info_append_uint32(db, "query-threshold", g_config.query_threshold);
	info_append_uint64(db, "query-untracked-time-ms", g_config.query_untracked_time_ms);
	info_append_uint32(db, "query-worker-threads", g_config.query_worker_threads);
	info_append_bool(db, "respond-client-on-master-completion", g_config.respond_client_on_master_completion);
	info_append_bool(db, "run-as-daemon", g_config.run_as_daemon);
	info_append_uint32(db, "scan-max-active", g_config.scan_max_active);
	info_append_uint32(db, "scan-max-done", g_config.scan_max_done);
	info_append_uint32(db, "scan-max-udf-transactions", g_config.scan_max_udf_transactions);
	info_append_uint32(db, "scan-threads", g_config.scan_threads);
	info_append_uint32(db, "sindex-builder-threads", g_config.sindex_builder_threads);

	if (g_config.sindex_data_max_memory != ULONG_MAX) {
		info_append_uint64(db, "sindex-data-max-memory", g_config.sindex_data_max_memory);
	}
	else {
		info_append_string(db, "sindex-data-max-memory", "ULONG_MAX");
	}

	info_append_bool(db, "sindex-gc-enable-histogram", g_config.sindex_gc_enable_histogram); // dynamic only
	info_append_uint32(db, "ticker-interval", g_config.ticker_interval);
	info_append_int(db, "transaction-max-ms", (int)(g_config.transaction_max_ns / 1000000));
	info_append_uint32(db, "transaction-pending-limit", g_config.transaction_pending_limit);
	info_append_bool(db, "transaction-repeatable-read", g_config.transaction_repeatable_read);
	info_append_uint32(db, "transaction-retry-ms", g_config.transaction_retry_ms);
	info_append_bool(db, "use-queue-per-device", g_config.use_queue_per_device);
	info_append_string(db, "work-directory", g_config.work_directory ? g_config.work_directory : "null");
	info_append_bool(db, "write-duplicate-resolution-disable", g_config.write_duplicate_resolution_disable);

#ifdef USE_ASM
	info_append_bool(db, "asmalloc-enabled", g_config.asmalloc_enabled);
#endif
	info_append_bool(db, "fabric-dump-msgs", g_config.fabric_dump_msgs);
	info_append_int(db, "max-msgs-per-type", (int)g_config.max_msgs_per_type);
#ifdef MEM_COUNT
	info_append_bool(db, "memory-accounting", g_config.memory_accounting);
#endif
	info_append_uint32(db, "prole-extra-ttl", g_config.prole_extra_ttl);
	info_append_bool(db, "non-master-sets-delete", g_config.non_master_sets_delete); // dynamic only
}


void
info_network_config_get(cf_dyn_buf *db)
{
	// Service:

	info_append_string(db, "service.address", g_config.socket.addr);
	info_append_int(db, "service.port", g_config.socket.port);

	if (g_config.external_address) {
		info_append_string(db, "service.access-address", g_config.external_address);
		info_append_bool(db, "virtual", g_config.is_external_address_virtual); // TODO - how to present?
	}

	if (g_config.alternate_address) {
		info_append_string(db, "service.alternate-address", g_config.alternate_address);
	}

	if (g_config.network_interface_name) {
		info_append_string(db, "service.network-interface-name", g_config.network_interface_name);
	}

	info_append_bool(db, "service.reuse-address", g_config.socket_reuse_addr);

	// Heartbeat:

	as_hb_info_config_get(db);

	// Fabric:

	info_append_int(db, "fabric.port", g_config.fabric_port);
	info_append_bool(db, "fabric.keepalive-enabled", g_config.fabric_keepalive_enabled);
	info_append_int(db, "fabric.keepalive-time", g_config.fabric_keepalive_time);
	info_append_int(db, "fabric.keepalive-intvl", g_config.fabric_keepalive_intvl);
	info_append_int(db, "fabric.keepalive-probes", g_config.fabric_keepalive_probes);
	info_append_int(db, "fabric.latency-max-ms", g_config.fabric_latency_max_ms);

	// Info:

	// network.info.port is the asd info port variable/output, This was chosen
	// because info.port conflicts with XDR config parameter. Ideally XDR should
	// use xdr.info.port and asd should use info.port.
	info_append_int(db, "info.port", g_config.info_port);
}


void
info_namespace_config_get(char* context, cf_dyn_buf *db)
{
	as_namespace *ns = as_namespace_get_byname(context);

	if (! ns) {
		cf_dyn_buf_append_string(db, "namespace not found;"); // TODO - start with "error"?
		return;
	}

	info_append_uint32(db, "repl-factor", (uint32_t)ns->replication_factor);
	info_append_uint64(db, "memory-size", ns->memory_size);
	info_append_uint64(db, "default-ttl", ns->default_ttl);

	info_append_bool(db, "enable-xdr", ns->enable_xdr);
	info_append_bool(db, "sets-enable-xdr", ns->sets_enable_xdr);
	info_append_bool(db, "ns-forward-xdr-writes", ns->ns_forward_xdr_writes);
	info_append_bool(db, "allow-nonxdr-writes", ns->ns_allow_nonxdr_writes);
	info_append_bool(db, "allow-xdr-writes", ns->ns_allow_xdr_writes);

	// Not true config, but act as config overrides:
	cf_hist_track_get_settings(ns->read_hist, db);
	cf_hist_track_get_settings(ns->query_hist, db);
	cf_hist_track_get_settings(ns->udf_hist, db);
	cf_hist_track_get_settings(ns->write_hist, db);

	info_append_uint32(db, "cold-start-evict-ttl", ns->cold_start_evict_ttl);

	if (ns->conflict_resolution_policy == AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_GENERATION) {
		info_append_string(db, "conflict-resolution-policy", "generation");
	}
	else if (ns->conflict_resolution_policy == AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME) {
		info_append_string(db, "conflict-resolution-policy", "last-update-time");
	}
	else {
		info_append_string(db, "conflict-resolution-policy", "undefined");
	}

	info_append_bool(db, "data-in-index", ns->data_in_index);
	info_append_bool(db, "disallow-null-setname", ns->disallow_null_setname);
	info_append_bool(db, "enable-benchmarks-batch-sub", ns->batch_sub_benchmarks_enabled);
	info_append_bool(db, "enable-benchmarks-read", ns->read_benchmarks_enabled);
	info_append_bool(db, "enable-benchmarks-storage", ns->storage_benchmarks_enabled);
	info_append_bool(db, "enable-benchmarks-udf", ns->udf_benchmarks_enabled);
	info_append_bool(db, "enable-benchmarks-udf-sub", ns->udf_sub_benchmarks_enabled);
	info_append_bool(db, "enable-benchmarks-write", ns->write_benchmarks_enabled);
	info_append_bool(db, "enable-hist-proxy", ns->proxy_hist_enabled);
	info_append_uint32(db, "evict-hist-buckets", ns->evict_hist_buckets);
	info_append_uint32(db, "evict-tenths-pct", ns->evict_tenths_pct);
	info_append_int(db, "high-water-disk-pct", (int)(ns->hwm_disk * 100));
	info_append_int(db, "high-water-memory-pct", (int)(ns->hwm_memory * 100));
	info_append_bool(db, "ldt-enabled", ns->ldt_enabled);
	info_append_uint32(db, "ldt-gc-rate", ns->ldt_gc_sleep_us / 1000000);
	info_append_uint32(db, "ldt-page-size", ns->ldt_page_size);
	info_append_uint64(db, "max-ttl", ns->max_ttl);
	info_append_uint32(db, "migrate-order", ns->migrate_order);
	info_append_uint32(db, "migrate-sleep", ns->migrate_sleep);
	// Note - no obj-size-hist-max, too much to reverse rounding algorithm.
	info_append_string(db, "read-consistency-level-override", NS_READ_CONSISTENCY_LEVEL_NAME());
	info_append_bool(db, "single-bin", ns->single_bin);
	info_append_int(db, "stop-writes-pct", (int)(ns->stop_writes_pct * 100));
	info_append_string(db, "write-commit-level-override", NS_WRITE_COMMIT_LEVEL_NAME());

	info_append_string(db, "storage-engine",
			(ns->storage_type == AS_STORAGE_ENGINE_MEMORY ? "memory" :
				(ns->storage_type == AS_STORAGE_ENGINE_SSD ? "device" :
					(ns->storage_type == AS_STORAGE_ENGINE_KV ? "kv" : "illegal"))));

	if (ns->storage_type == AS_STORAGE_ENGINE_SSD) {
		for (int i = 0; i < AS_STORAGE_MAX_DEVICES; i++) {
			if (! ns->storage_devices[i]) {
				break;
			}

			info_append_string(db, "storage-engine.device", ns->storage_devices[i]);
		}

		for (int i = 0; i < AS_STORAGE_MAX_FILES; i++) {
			if (! ns->storage_files[i]) {
				break;
			}

			info_append_string(db, "storage-engine.file", ns->storage_files[i]);
		}

		// TODO - how to report the shadows?

		info_append_uint64(db, "storage-engine.filesize", ns->storage_filesize);
		info_append_string(db, "storage-engine.scheduler-mode", ns->storage_scheduler_mode ? ns->storage_scheduler_mode : "null");
		info_append_uint32(db, "storage-engine.write-block-size", ns->storage_write_block_size);
		info_append_bool(db, "storage-engine.data-in-memory", ns->storage_data_in_memory);
		info_append_bool(db, "storage-engine.cold-start-empty", ns->storage_cold_start_empty);
		info_append_uint32(db, "storage-engine.defrag-lwm-pct", ns->storage_defrag_lwm_pct);
		info_append_uint32(db, "storage-engine.defrag-queue-min", ns->storage_defrag_queue_min);
		info_append_uint32(db, "storage-engine.defrag-sleep", ns->storage_defrag_sleep);
		info_append_int(db, "storage-engine.defrag-startup-minimum", ns->storage_defrag_startup_minimum);
		info_append_bool(db, "storage-engine.disable-odirect", ns->storage_disable_odirect);
		info_append_bool(db, "storage-engine.enable-osync", ns->storage_enable_osync);
		info_append_uint64(db, "storage-engine.flush-max-ms", ns->storage_flush_max_us / 1000);
		info_append_uint64(db, "storage-engine.fsync-max-sec", ns->storage_fsync_max_us / 1000000);
		info_append_uint64(db, "storage-engine.max-write-cache", ns->storage_max_write_cache);
		info_append_uint32(db, "storage-engine.min-avail-pct", ns->storage_min_avail_pct);
		info_append_uint32(db, "storage-engine.post-write-queue", ns->storage_post_write_queue);
		info_append_uint32(db, "storage-engine.write-threads", ns->storage_write_threads);
	}

	if (ns->storage_type == AS_STORAGE_ENGINE_KV) {
		for (int i = 0; i < AS_STORAGE_MAX_DEVICES; i++) {
			if (! ns->storage_devices[i]) {
				break;
			}

			info_append_string(db, "storage-engine.device", ns->storage_devices[i]);
		}

		info_append_uint64(db, "storage-engine.filesize", ns->storage_filesize);
		info_append_uint32(db, "storage-engine.read-block-size", ns->storage_read_block_size);
		info_append_uint32(db, "storage-engine.write-block-size", ns->storage_write_block_size);
		info_append_uint32(db, "storage-engine.num-write-blocks", ns->storage_num_write_blocks);
		info_append_bool(db, "storage-engine.cond-write", ns->cond_write);
	}

	if (ns->sindex_data_max_memory != ULONG_MAX) {
		info_append_uint64(db, "sindex.data-max-memory", ns->sindex_data_max_memory);
	}
	else {
		info_append_string(db, "sindex.data-max-memory", "ULONG_MAX");
	}

	info_append_uint32(db, "sindex.num-partitions", ns->sindex_num_partitions);

	info_append_bool(db, "geo2dsphere-within.strict", ns->geo2dsphere_within_strict);
	info_append_uint32(db, "geo2dsphere-within.min-level", (uint32_t)ns->geo2dsphere_within_min_level);
	info_append_uint32(db, "geo2dsphere-within.max-level", (uint32_t)ns->geo2dsphere_within_max_level);
	info_append_uint32(db, "geo2dsphere-within.max-cells", (uint32_t)ns->geo2dsphere_within_max_cells);
	info_append_uint32(db, "geo2dsphere-within.level-mod", (uint32_t)ns->geo2dsphere_within_level_mod);
	info_append_uint32(db, "geo2dsphere-within.earth-radius-meters", ns->geo2dsphere_within_earth_radius_meters);
}


void
info_cluster_config_get(cf_dyn_buf *db)
{
	info_append_string(db, "mode", cc_mode_str[g_config.cluster_mode]);
	info_append_uint32(db, "self-group-id", (uint32_t)g_config.cluster.cl_self_group);
	info_append_uint32(db, "self-node-id", g_config.cluster.cl_self_node);
}


// TODO - security API?
void
info_security_config_get(cf_dyn_buf *db)
{
	info_append_bool(db, "enable-security", g_config.sec_cfg.security_enabled);
	info_append_uint32(db, "privilege-refresh-period", g_config.sec_cfg.privilege_refresh_period);
	info_append_uint32(db, "report-authentication-sinks", g_config.sec_cfg.report.authentication);
	info_append_uint32(db, "report-data-op-sinks", g_config.sec_cfg.report.data_op);
	info_append_uint32(db, "report-sys-admin-sinks", g_config.sec_cfg.report.sys_admin);
	info_append_uint32(db, "report-user-admin-sinks", g_config.sec_cfg.report.user_admin);
	info_append_uint32(db, "report-violation-sinks", g_config.sec_cfg.report.violation);
	info_append_int(db, "syslog-local", g_config.sec_cfg.syslog_local);
}


void
info_command_config_get_with_params(char *name, char *params, cf_dyn_buf *db)
{
	char context[1024];
	int context_len = sizeof(context);

	if (as_info_parameter_get(params, "context", context, &context_len) != 0) {
		cf_dyn_buf_append_string(db, "Error: Invalid get-config parameter;");
		return;
	}

	if (strcmp(context, "service") == 0) {
		info_service_config_get(db);
	}
	else if (strcmp(context, "network") == 0) {
		info_network_config_get(db);
	}
	else if (strcmp(context, "namespace") == 0) {
		context_len = sizeof(context);

		if (as_info_parameter_get(params, "id", context, &context_len) != 0) {
			cf_dyn_buf_append_string(db, "Error:invalid id;");
			return;
		}

		info_namespace_config_get(context, db);
	}
	else if (strcmp(context, "cluster") == 0) {
		info_cluster_config_get(db);
	}
	else if (strcmp(context, "security") == 0) {
		info_security_config_get(db);
	}
	else if (strcmp(context, "xdr") == 0) {
		as_xdr_get_config(db);
	}
	else {
		cf_dyn_buf_append_string(db, "Error:Invalid context;");
	}
}


int
info_command_config_get(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "config-get command received: params %s", params);

	if (params && *params != 0) {
		info_command_config_get_with_params(name, params, db);
		cf_dyn_buf_chomp(db);
		return 0;
	}

	// We come here when context is not mentioned.
	// In that case we want to print everything.
	info_service_config_get(db);
	info_network_config_get(db);
	info_cluster_config_get(db);
	info_security_config_get(db);
	as_xdr_get_config(db);

	cf_dyn_buf_chomp(db);

	return 0;
}


//
// config-set:context=service;variable=value;
// config-set:context=network;variable=heartbeat.value;
// config-set:context=namespace;id=test;variable=value;
//
int
info_command_config_set(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "config-set command received: params %s", params);

	char context[1024];
	int  context_len = sizeof(context);
	int val;
	char bool_val[2][6] = {"false", "true"};
	bool print_command = true;

	if (0 != as_info_parameter_get(params, "context", context, &context_len))
		goto Error;
	if (strcmp(context, "service") == 0) {
		context_len = sizeof(context);
		if (0 == as_info_parameter_get(params, "transaction-retry-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (val == 0)
				goto Error;
			cf_info(AS_INFO, "Changing value of transaction-retry-ms from %d to %d ", g_config.transaction_retry_ms, val);
			g_config.transaction_retry_ms = val;
		}
		else if (0 == as_info_parameter_get(params, "transaction-max-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of transaction-retry-ms from %"PRIu64" to %d ", (g_config.transaction_max_ns / 1000000), val);
			g_config.transaction_max_ns = (uint64_t)val * 1000000;
		}
		else if (0 == as_info_parameter_get(params, "transaction-pending-limit", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of transaction-pending-limit from %d to %d ", g_config.transaction_pending_limit, val);
			g_config.transaction_pending_limit = val;
		}
		else if (0 == as_info_parameter_get(params, "transaction-repeatable-read", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of transaction-repeatable-read from %s to %s", bool_val[g_config.transaction_repeatable_read], context);
				g_config.transaction_repeatable_read = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of transaction-repeatable-read from %s to %s", bool_val[g_config.transaction_repeatable_read], context);
				g_config.transaction_repeatable_read = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "ticker-interval", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of ticker-interval from %d to %d ", g_config.ticker_interval, val);
			g_config.ticker_interval = val;
		}
		else if (0 == as_info_parameter_get(params, "ldt-benchmarks", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				clear_ldt_histograms();
				cf_info(AS_INFO, "Changing value of ldt-benchmarks from %s to %s", bool_val[g_config.ldt_benchmarks], context);
				g_config.ldt_benchmarks = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of ldt-benchmarks from %s to %s", bool_val[g_config.ldt_benchmarks], context);
				g_config.ldt_benchmarks = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "scan-max-active", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (val < 0 || val > 200) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of scan-max-active from %d to %d ", g_config.scan_max_active, val);
			g_config.scan_max_active = val;
			as_scan_limit_active_jobs(g_config.scan_max_active);
		}
		else if (0 == as_info_parameter_get(params, "scan-max-done", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (val < 0 || val > 1000) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of scan-max-done from %d to %d ", g_config.scan_max_done, val);
			g_config.scan_max_done = val;
			as_scan_limit_finished_jobs(g_config.scan_max_done);
		}
		else if (0 == as_info_parameter_get(params, "scan-max-udf-transactions", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of scan-max-udf-transactions from %d to %d ", g_config.scan_max_udf_transactions, val);
			g_config.scan_max_udf_transactions = val;
		}
		else if (0 == as_info_parameter_get(params, "scan-threads", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (val < 0 || val > 32) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of scan-threads from %d to %d ", g_config.scan_threads, val);
			g_config.scan_threads = val;
			as_scan_resize_thread_pool(g_config.scan_threads);
		}
		else if (0 == as_info_parameter_get(params, "batch-index-threads", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (0 != as_batch_threads_resize(val))
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "batch-threads", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			if (0 != as_batch_direct_threads_resize(val))
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "batch-max-requests", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of batch-max-requests from %d to %d ", g_config.batch_max_requests, val);
			g_config.batch_max_requests = val;
		}
		else if (0 == as_info_parameter_get(params, "batch-max-buffers-per-queue", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of batch-max-buffers-per-queue from %d to %d ", g_config.batch_max_buffers_per_queue, val);
			g_config.batch_max_buffers_per_queue = val;
		}
		else if (0 == as_info_parameter_get(params, "batch-max-unused-buffers", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of batch-max-unused-buffers from %d to %d ", g_config.batch_max_unused_buffers, val);
			g_config.batch_max_unused_buffers = val;
		}
		else if (0 == as_info_parameter_get(params, "batch-priority", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of batch-priority from %d to %d ", g_config.batch_priority, val);
			g_config.batch_priority = val;
		}
		else if (0 == as_info_parameter_get(params, "proto-fd-max", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of proto-fd-max from %d to %d ", g_config.n_proto_fd_max, val);
			g_config.n_proto_fd_max = val;
		}
		else if (0 == as_info_parameter_get(params, "proto-fd-idle-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of proto-fd-idle-ms from %d to %d ", g_config.proto_fd_idle_ms, val);
			g_config.proto_fd_idle_ms = val;
		}
		else if (0 == as_info_parameter_get(params, "proto-slow-netio-sleep-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of proto-slow-netio-sleep-ms from %d to %d ", g_config.proto_slow_netio_sleep_ms, val);
			g_config.proto_slow_netio_sleep_ms = val;
		}
		else if (0 == as_info_parameter_get(params, "nsup-delete-sleep", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of nsup-delete-sleep from %d to %d ", g_config.nsup_delete_sleep, val);
			g_config.nsup_delete_sleep = val;
		}
		else if (0 == as_info_parameter_get(params, "nsup-period", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of nsup-period from %d to %d ", g_config.nsup_period, val);
			g_config.nsup_period = val;
		}
		else if (0 == as_info_parameter_get(params, "paxos-retransmit-period", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of paxos-retransmit-period from %d to %d ", g_config.paxos_retransmit_period, val);
			g_config.paxos_retransmit_period = val;
		}
		else if (0 == as_info_parameter_get(params, "paxos-max-cluster-size", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || (1 > val) ||
			    (val > AS_CLUSTER_SZ) ||
			    !as_hb_max_cluster_size_isvalid(val))
				goto Error;
			cf_info(AS_INFO, "Changing value of paxos-max-cluster-size from %d to %d ", g_config.paxos_max_cluster_size, val);
			g_config.paxos_max_cluster_size = val;
		}
		else if (0 == as_info_parameter_get(params, "paxos-protocol", context, &context_len)) {
			paxos_protocol_enum protocol = (!strcmp(context, "v1") ? AS_PAXOS_PROTOCOL_V1 :
											(!strcmp(context, "v2") ? AS_PAXOS_PROTOCOL_V2 :
											 (!strcmp(context, "v3") ? AS_PAXOS_PROTOCOL_V3 :
											  (!strcmp(context, "v4") ? AS_PAXOS_PROTOCOL_V4 :
											   (!strcmp(context, "none") ? AS_PAXOS_PROTOCOL_NONE :
												AS_PAXOS_PROTOCOL_UNDEF)))));
			if (AS_PAXOS_PROTOCOL_UNDEF == protocol)
				goto Error;
			if (0 > as_paxos_set_protocol(protocol))
				goto Error;
			cf_info(AS_INFO, "Changing value of paxos-protocol version to %s", context);
		}
		else if (0 == as_info_parameter_get(params, "paxos-recovery-policy", context, &context_len)) {
			paxos_recovery_policy_enum policy = ((!strcmp(context, "auto-reset-master") ? AS_PAXOS_RECOVERY_POLICY_AUTO_RESET_MASTER : AS_PAXOS_RECOVERY_POLICY_UNDEF));
			if (AS_PAXOS_RECOVERY_POLICY_UNDEF == policy)
				goto Error;
			if (0 > as_paxos_set_recovery_policy(policy))
				goto Error;
			cf_info(AS_INFO, "Changing value of paxos-recovery-policy to %s", context);
		}
		else if (0 == as_info_parameter_get( params, "cluster-id", context, &context_len)){
			char* cluster_id = context;
			if (strcmp(cluster_id, "none") == 0) {
				cluster_id = "";
			}
			if (!as_config_cluster_id_set(cluster_id)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of cluster-id to '%s'", cluster_id);
		}
		else if (0 == as_info_parameter_get(params, "migrate-max-num-incoming", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || (0 > val))
				goto Error;
			cf_info(AS_INFO, "Changing value of migrate-max-num-incoming from %d to %d ", g_config.migrate_max_num_incoming, val);
			g_config.migrate_max_num_incoming = val;
		}
		else if (0 == as_info_parameter_get(params, "migrate-rx-lifetime-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || (0 > val))
				goto Error;
			cf_info(AS_INFO, "Changing value of migrate-rx-lifetime-ms from %d to %d ", g_config.migrate_rx_lifetime_ms, val);
			g_config.migrate_rx_lifetime_ms = val;
		}
		else if (0 == as_info_parameter_get(params, "migrate-threads", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || (0 > val) || (MAX_NUM_MIGRATE_XMIT_THREADS < val))
				goto Error;
			cf_info(AS_INFO, "Changing value of migrate-theads from %d to %d ", g_config.n_migrate_threads, val);
			as_migrate_set_num_xmit_threads(val);
		}
		else if (0 == as_info_parameter_get(params, "generation-disable", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of generation-disable from %s to %s", bool_val[g_config.generation_disable], context);
				g_config.generation_disable = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of generation-disable from %s to %s", bool_val[g_config.generation_disable], context);
				g_config.generation_disable = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "write-duplicate-resolution-disable", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of write-duplicate-resolution-disable from %s to %s", bool_val[g_config.write_duplicate_resolution_disable], context);
				g_config.write_duplicate_resolution_disable = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of write-duplicate-resolution-disable from %s to %s", bool_val[g_config.write_duplicate_resolution_disable], context);
				g_config.write_duplicate_resolution_disable = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "respond-client-on-master-completion", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of respond-client-on-master-completion from %s to %s", bool_val[g_config.respond_client_on_master_completion], context);
				g_config.respond_client_on_master_completion = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of respond-client-on-master-completion from %s to %s", bool_val[g_config.respond_client_on_master_completion], context);
				g_config.respond_client_on_master_completion = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "use-queue-per-device", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of use-queue-per-device from %s to %s", bool_val[g_config.use_queue_per_device], context);
				g_config.use_queue_per_device = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of use-queue-per-device from %s to %s", bool_val[g_config.use_queue_per_device], context);
				g_config.use_queue_per_device = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "allow-inline-transactions", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of allow-inline-transactions from %s to %s", bool_val[g_config.allow_inline_transactions], context);
				g_config.allow_inline_transactions = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of allow-inline-transactions from %s to %s", bool_val[g_config.allow_inline_transactions], context);
				g_config.allow_inline_transactions = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "non-master-sets-delete", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of non-master-sets-delete from %s to %s", bool_val[g_config.non_master_sets_delete], context);
				g_config.non_master_sets_delete = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of non-master-sets-delete from %s to %s", bool_val[g_config.non_master_sets_delete], context);
				g_config.non_master_sets_delete = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "prole-extra-ttl", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of prole-extra-ttl from %d to %d ", g_config.prole_extra_ttl, val);
			g_config.prole_extra_ttl = val;
		}
		else if (0 == as_info_parameter_get(params, "max-msgs-per-type", context, &context_len)) {
			if ((0 != cf_str_atoi(context, &val)) || (val == 0))
				goto Error;
			cf_info(AS_INFO, "Changing value of max-msgs-per-type from %"PRId64" to %d ", g_config.max_msgs_per_type, val);
			msg_set_max_msgs_per_type(g_config.max_msgs_per_type = (val >= 0 ? val : -1));
		}
#ifdef MEM_COUNT
		else if (0 == as_info_parameter_get(params, "memory-accounting", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				g_config.memory_accounting = true;
				cf_info(AS_INFO, "Changing value of memory-accounting from %s to %s", bool_val[g_config.memory_accounting], context);
				mem_count_init(MEM_COUNT_ENABLE_DYNAMIC);
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				g_config.memory_accounting = false;
				cf_info(AS_INFO, "Changing value of memory-accounting from %s to %s", bool_val[g_config.memory_accounting], context);
				mem_count_init(MEM_COUNT_DISABLE);
			}
			else
				goto Error;
		}
#endif
		else if (0 == as_info_parameter_get(params, "query-buf-size", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "query-buf-size = %"PRIu64"", val);
			if (val < 1024) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-buf-size from %"PRIu64" to %"PRIu64"", g_config.query_buf_size, val);
			g_config.query_buf_size = val;
		}
		else if (0 == as_info_parameter_get(params, "query-threshold", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "query-threshold = %"PRIu64"", val);
			if (val <= 0) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-threshold from %u to %"PRIu64, g_config.query_threshold, val);
			g_config.query_threshold = val;
		}
		else if (0 == as_info_parameter_get(params, "query-untracked-time-ms", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "query-untracked-time = %"PRIu64" milli seconds", val);
			if (val < 0) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-untracked-time from %"PRIu64" milli seconds to %"PRIu64" milli seconds",
						g_config.query_untracked_time_ms, val);
			g_config.query_untracked_time_ms = val;
		}
		else if (0 == as_info_parameter_get(params, "query-rec-count-bound", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "query-rec-count-bound = %"PRIu64"", val);
			if (val <= 0) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-rec-count-bound from %"PRIu64" to %"PRIu64" ", g_config.query_rec_count_bound, val);
			g_config.query_rec_count_bound = val;
		}
		else if (0 == as_info_parameter_get(params, "sindex-builder-threads", context, &context_len)) {
			int val = 0;
			if (0 != cf_str_atoi(context, &val) || (val > MAX_SINDEX_BUILDER_THREADS)) {
				cf_warning(AS_INFO, "sindex-builder-threads: value must be <= %d, not %s", MAX_SINDEX_BUILDER_THREADS, context);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of sindex-builder-threads from %u to %d", g_config.sindex_builder_threads, val);
			g_config.sindex_builder_threads = (uint32_t)val;
			as_sbld_resize_thread_pool(g_config.sindex_builder_threads);
		}
		else if (0 == as_info_parameter_get(params, "sindex-data-max-memory", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "sindex-data-max-memory = %"PRIu64"", val);
			if (val > g_config.sindex_data_max_memory) {
				g_config.sindex_data_max_memory = val;
			}
			if (val < (g_config.sindex_data_max_memory / 2L)) { // protect so someone does not reduce memory to below 1/2 current value
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of sindex-data-max-memory from %"PRIu64" to %"PRIu64, g_config.sindex_data_max_memory, val);
			g_config.sindex_data_max_memory = val;
		}
		else if (0 == as_info_parameter_get(params, "query-threads", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-threads = %"PRIu64, val);
			if (val == 0) {
				cf_warning(AS_INFO, "query-threads should be a number %s", context);
				goto Error;
			}
			int old_val = g_config.query_threads;
			int new_val = 0;
			if (as_query_reinit(val, &new_val) != AS_QUERY_OK) {
				cf_warning(AS_INFO, "Config not changed.");
				goto Error;
			}

			cf_info(AS_INFO, "Changing value of query-threads from %d to %d",
					old_val, new_val);
		}
		else if (0 == as_info_parameter_get(params, "query-worker-threads", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-worker-threads = %"PRIu64, val);
			if (val == 0) {
				cf_warning(AS_INFO, "query-worker-threads should be a number %s", context);
				goto Error;
			}
			int old_val = g_config.query_threads;
			int new_val = 0;
			if (as_query_worker_reinit(val, &new_val) != AS_QUERY_OK) {
				cf_warning(AS_INFO, "Config not changed.");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-worker-threads from %d to %d",
					old_val, new_val);
		}
		else if (0 == as_info_parameter_get(params, "query-priority", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query_priority = %"PRIu64, val);
			if (val == 0) {
				cf_warning(AS_INFO, "query_priority should be a number %s", context);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-priority from %d to %"PRIu64, g_config.query_priority, val);
			g_config.query_priority = val;
		}
		else if (0 == as_info_parameter_get(params, "query-priority-sleep-us", context, &context_len)) {
			uint64_t val = atoll(context);
			if(val == 0) {
				cf_warning(AS_INFO, "query_sleep should be a number %s", context);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-sleep from %"PRIu64" uSec to %"PRIu64" uSec ", g_config.query_sleep_us, val);
			g_config.query_sleep_us = val;
		}
		else if (0 == as_info_parameter_get(params, "query-batch-size", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-batch-size = %"PRIu64, val);
			if((int)val <= 0) {
				cf_warning(AS_INFO, "query-batch-size should be a positive number");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-batch-size from %d to %"PRIu64, g_config.query_bsize, val);
			g_config.query_bsize = val;
		}
		else if (0 == as_info_parameter_get(params, "query-req-max-inflight", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-req-max-inflight = %"PRIu64, val);
			if((int)val <= 0) {
				cf_warning(AS_INFO, "query-req-max-inflight should be a positive number");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-req-max-inflight from %d to %"PRIu64, g_config.query_req_max_inflight, val);
			g_config.query_req_max_inflight = val;
		}
		else if (0 == as_info_parameter_get(params, "query-bufpool-size", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-bufpool-size = %"PRIu64, val);
			if((int)val <= 0) {
				cf_warning(AS_INFO, "query-bufpool-size should be a positive number");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-bufpool-size from %d to %"PRIu64, g_config.query_bufpool_size, val);
			g_config.query_bufpool_size = val;
		}
		else if (0 == as_info_parameter_get(params, "query-in-transaction-thread", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of query-in-transaction-thread  from %s to %s", bool_val[g_config.query_in_transaction_thr], context);
				g_config.query_in_transaction_thr = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of query-in-transaction-thread  from %s to %s", bool_val[g_config.query_in_transaction_thr], context);
				g_config.query_in_transaction_thr = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "query-req-in-query-thread", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of query-req-in-query-thread from %s to %s", bool_val[g_config.query_req_in_query_thread], context);
				g_config.query_req_in_query_thread = true;

			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of query-req-in-query-thread from %s to %s", bool_val[g_config.query_req_in_query_thread], context);
				g_config.query_req_in_query_thread = false;
			}
			else
				goto Error;
		}
		else if (0 == as_info_parameter_get(params, "query-short-q-max-size", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-short-q-max-size = %"PRIu64, val);
			if((int)val <= 0) {
				cf_warning(AS_INFO, "query-short-q-max-size should be a positive number");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-short-q-max-size from %d to %"PRIu64, g_config.query_short_q_max_size, val);
			g_config.query_short_q_max_size = val;
		}
		else if (0 == as_info_parameter_get(params, "query-long-q-max-size", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_info(AS_INFO, "query-long-q-max-size = %"PRIu64, val);
			if((int)val <= 0) {
				cf_warning(AS_INFO, "query-long-q-max-size should be a positive number");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of query-longq-max-size from %d to %"PRIu64, g_config.query_long_q_max_size, val);
			g_config.query_long_q_max_size = val;
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-svc", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-svc to %s", context);
				g_config.svc_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-svc to %s", context);
				g_config.svc_benchmarks_enabled = false;
				histogram_clear(g_stats.svc_demarshal_hist);
				histogram_clear(g_stats.svc_queue_hist);
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-hist-info", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-hist-info to %s", context);
				g_config.info_hist_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-hist-info to %s", context);
				g_config.info_hist_enabled = false;
				histogram_clear(g_stats.info_hist);
			}
		}
		else if (0 == as_info_parameter_get(params, "sindex-gc-enable-histogram", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of sindex-gc-enable-histogram to %s", context);
				g_config.sindex_gc_enable_histogram = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of sindex-gc-enable-histogram from to %s", context);
				g_config.sindex_gc_enable_histogram = false;
			}
		}
		else if (0 == as_info_parameter_get(params, "query-microbenchmark", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of query-enable-histogram to %s", context);
				g_config.query_enable_histogram = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of query-enable-histogram to %s", context);
				g_config.query_enable_histogram = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "query-pre-reserve-partitions", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of query-pre-reserve-partitions to %s", context);
				g_config.partitions_pre_reserved = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of query-pre-reserve-partitions to %s", context);
				g_config.partitions_pre_reserved = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "clock-skew-max-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			cf_info(AS_INFO, "Changing value of clock-skew-max-ms from %d to %d ", g_config.clock_skew_max_ms, val);
			g_config.clock_skew_max_ms = val;
		}
		else {
			goto Error;
		}
	}
	else if (strcmp(context, "network") == 0) {
		context_len = sizeof(context);
		if (0 == as_info_parameter_get(params, "heartbeat.interval", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			as_hb_tx_interval_set(val);
		}
		else if (0 == as_info_parameter_get(params, "heartbeat.timeout", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			as_hb_max_intervals_missed_set(val);
		}
		else if (0 == as_info_parameter_get(params, "heartbeat.fabric-grace-factor", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			as_hb_fabric_grace_factor_set(val);
		}
		else if (0 == as_info_parameter_get(params, "heartbeat.mtu", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val))
				goto Error;
			as_hb_override_mtu_set(val);
		}
		else if (0 == as_info_parameter_get(params, "heartbeat.protocol", context, &context_len)) {
			hb_protocol_enum protocol = (!strcmp(context, "v1") ? AS_HB_PROTOCOL_V1 :
										 (!strcmp(context, "v2") ? AS_HB_PROTOCOL_V2 :
										  (!strcmp(context, "reset") ? AS_HB_PROTOCOL_RESET :
										   (!strcmp(context, "none") ? AS_HB_PROTOCOL_NONE :
											AS_HB_PROTOCOL_UNDEF))));
			if (AS_HB_PROTOCOL_UNDEF == protocol)
				goto Error;
			cf_info(AS_INFO, "Changing value of heartbeat protocol version to %s", context);
			if (0 > as_hb_set_protocol(protocol))
				goto Error;
		}
		else
			goto Error;
	}
	else if (strcmp(context, "namespace") == 0) {
		context_len = sizeof(context);
		if (0 != as_info_parameter_get(params, "id", context, &context_len))
			goto Error;
		as_namespace *ns = as_namespace_get_byname(context);
		if (!ns)
			goto Error;

		context_len = sizeof(context);
		// configure namespace/set related parameters:
		if (0 == as_info_parameter_get(params, "set", context, &context_len)) {
			// checks if there is a vmap set with the same name and if so returns a ptr to it
			// if not, it creates an set structure, initializes it and returns a ptr to it.
			as_set * p_set = as_namespace_init_set(ns, context);
			cf_debug(AS_INFO, "set name is %s\n", p_set->name);
			context_len = sizeof(context);
			if (0 == as_info_parameter_get(params, "set-enable-xdr", context, &context_len) ||
					0 == as_info_parameter_get(params, "enable-xdr", context, &context_len)) {
				// TODO - make sure context is null-terminated.
				if ((strncmp(context, "true", 4) == 0) || (strncmp(context, "yes", 3) == 0)) {
					cf_info(AS_INFO, "Changing value of set-enable-xdr of ns %s set %s to %s", ns->name, p_set->name, context);
					cf_atomic32_set(&p_set->enable_xdr, AS_SET_ENABLE_XDR_TRUE);
				}
				else if ((strncmp(context, "false", 5) == 0) || (strncmp(context, "no", 2) == 0)) {
					cf_info(AS_INFO, "Changing value of set-enable-xdr of ns %s set %s to %s", ns->name, p_set->name, context);
					cf_atomic32_set(&p_set->enable_xdr, AS_SET_ENABLE_XDR_FALSE);
				}
				else if (strncmp(context, "use-default", 11) == 0) {
					cf_info(AS_INFO, "Changing value of set-enable-xdr of ns %s set %s to %s", ns->name, p_set->name, context);
					cf_atomic32_set(&p_set->enable_xdr, AS_SET_ENABLE_XDR_DEFAULT);
				}
				else {
					goto Error;
				}
			}
			else if (0 == as_info_parameter_get(params, "set-disable-eviction", context, &context_len) ||
					0 == as_info_parameter_get(params, "disable-eviction", context, &context_len)) {
				if ((strncmp(context, "true", 4) == 0) || (strncmp(context, "yes", 3) == 0)) {
					cf_info(AS_INFO, "Changing value of set-disable-eviction of ns %s set %s to %s", ns->name, p_set->name, context);
					DISABLE_SET_EVICTION(p_set, true);
				}
				else if ((strncmp(context, "false", 5) == 0) || (strncmp(context, "no", 2) == 0)) {
					cf_info(AS_INFO, "Changing value of set-disable-eviction of ns %s set %s to %s", ns->name, p_set->name, context);
					DISABLE_SET_EVICTION(p_set, false);
				}
				else {
					goto Error;
				}
			}
			else if (0 == as_info_parameter_get(params, "set-stop-writes-count", context, &context_len) ||
					0 == as_info_parameter_get(params, "stop-writes-count", context, &context_len)) {
				uint64_t val = atoll(context);
				cf_info(AS_INFO, "Changing value of set-stop-writes-count of ns %s set %s to %lu", ns->name, p_set->name, val);
				cf_atomic64_set(&p_set->stop_writes_count, val);
			}
			else if (0 == as_info_parameter_get(params, "set-delete", context, &context_len) ||
					0 == as_info_parameter_get(params, "delete", context, &context_len)) {
				if ((strncmp(context, "true", 4) == 0) || (strncmp(context, "yes", 3) == 0)) {
					cf_info(AS_INFO, "Changing value of set-delete of ns %s set %s to %s", ns->name, p_set->name, context);
					SET_DELETED_ON(p_set);
				}
				else if ((strncmp(context, "false", 5) == 0) || (strncmp(context, "no", 2) == 0)) {
					cf_info(AS_INFO, "Changing value of set-delete of ns %s set %s to %s", ns->name, p_set->name, context);
					SET_DELETED_OFF(p_set);
				}
				else {
					goto Error;
				}
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "memory-size", context, &context_len)) {
			uint64_t val;

			if (0 != cf_str_atoi_u64(context, &val)) {
				goto Error;
			}
			cf_debug(AS_INFO, "memory-size = %"PRIu64"", val);
			if (val > ns->memory_size)
				ns->memory_size = val;
			if (val < (ns->memory_size / 2L)) { // protect so someone does not reduce memory to below 1/2 current value
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of memory-size of ns %s from %"PRIu64" to %"PRIu64, ns->name, ns->memory_size, val);
			ns->memory_size = val;
		}
		else if (0 == as_info_parameter_get(params, "high-water-disk-pct", context, &context_len)) {
			cf_info(AS_INFO, "Changing value of high-water-disk-pct of ns %s from %1.3f to %1.3f ", ns->name, ns->hwm_disk, atof(context) / (float)100);
			ns->hwm_disk = atof(context) / (float)100;
		}
		else if (0 == as_info_parameter_get(params, "high-water-memory-pct", context, &context_len)) {
			cf_info(AS_INFO, "Changing value of high-water-memory-pct memory of ns %s from %1.3f to %1.3f ", ns->name, ns->hwm_memory, atof(context) / (float)100);
			ns->hwm_memory = atof(context) / (float)100;
		}
		else if (0 == as_info_parameter_get(params, "evict-tenths-pct", context, &context_len)) {
			cf_info(AS_INFO, "Changing value of evict-tenths-pct memory of ns %s from %d to %d ", ns->name, ns->evict_tenths_pct, atoi(context));
			ns->evict_tenths_pct = atoi(context);
		}
		else if (0 == as_info_parameter_get(params, "evict-hist-buckets", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || val < 100 || val > 10000000) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of evict-hist-buckets of ns %s from %u to %d ", ns->name, ns->evict_hist_buckets, val);
			ns->evict_hist_buckets = (uint32_t)val;
		}
		else if (0 == as_info_parameter_get(params, "stop-writes-pct", context, &context_len)) {
			cf_info(AS_INFO, "Changing value of stop-writes-pct memory of ns %s from %1.3f to %1.3f ", ns->name, ns->stop_writes_pct, atof(context) / (float)100);
			ns->stop_writes_pct = atof(context) / (float)100;
		}
		else if (0 == as_info_parameter_get(params, "default-ttl", context, &context_len)) {
			uint64_t val;
			if (cf_str_atoi_seconds(context, &val) != 0) {
				cf_warning(AS_INFO, "default-ttl must be an unsigned number with time unit (s, m, h, or d)");
				goto Error;
			}
			if (val > ns->max_ttl) {
				cf_warning(AS_INFO, "default-ttl must be <= max-ttl (%lu seconds)", ns->max_ttl);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of default-ttl memory of ns %s from %"PRIu64" to %"PRIu64" ", ns->name, ns->default_ttl, val);
			ns->default_ttl = val;
		}
		else if (0 == as_info_parameter_get(params, "max-ttl", context, &context_len)) {
			uint64_t val;
			if (cf_str_atoi_seconds(context, &val) != 0) {
				cf_warning(AS_INFO, "max-ttl must be an unsigned number with time unit (s, m, h, or d)");
				goto Error;
			}
			if (val == 0 || val > MAX_ALLOWED_TTL) {
				cf_warning(AS_INFO, "max-ttl must be non-zero and <= %u seconds", MAX_ALLOWED_TTL);
				goto Error;
			}
			if (val < ns->default_ttl) {
				cf_warning(AS_INFO, "max-ttl must be >= default-ttl (%lu seconds)", ns->default_ttl);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of max-ttl memory of ns %s from %"PRIu64" to %"PRIu64" ", ns->name, ns->max_ttl, val);
			ns->max_ttl = val;
		}
		else if (0 == as_info_parameter_get(params, "migrate-order", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || val < 1 || val > 10) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of migrate-order of ns %s from %u to %d", ns->name, ns->migrate_order, val);
			ns->migrate_order = (uint32_t)val;
		}
		else if (0 == as_info_parameter_get(params, "migrate-sleep", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of migrate-sleep of ns %s from %u to %d", ns->name, ns->migrate_sleep, val);
			ns->migrate_sleep = (uint32_t)val;
		}
		else if (0 == as_info_parameter_get(params, "obj-size-hist-max", context, &context_len)) {
			uint32_t hist_max = (uint32_t)atoi(context);
			uint32_t round_to = OBJ_SIZE_HIST_NUM_BUCKETS;
			uint32_t round_max = hist_max ? ((hist_max + round_to - 1) / round_to) * round_to : round_to;
			if (round_max != hist_max) {
				cf_info(AS_INFO, "rounding obj-size-hist-max %u up to %u", hist_max, round_max);
			}
			cf_info(AS_INFO, "Changing value of obj-size-hist-max of ns %s to %u", ns->name, round_max);
			cf_atomic32_set(&ns->obj_size_hist_max, round_max); // in 128-byte blocks
		}
		else if (0 == as_info_parameter_get(params, "conflict-resolution-policy", context, &context_len)) {
			if (strncmp(context, "generation", 10) == 0) {
				cf_info(AS_INFO, "Changing value of conflict-resolution-policy of ns %s from %d to %s", ns->name, ns->conflict_resolution_policy, context);
				ns->conflict_resolution_policy = AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_GENERATION;
			}
			else if (strncmp(context, "last-update-time", 16) == 0) {
				cf_info(AS_INFO, "Changing value of conflict-resolution-policy of ns %s from %d to %s", ns->name, ns->conflict_resolution_policy, context);
				ns->conflict_resolution_policy = AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "ldt-enabled", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of ldt-enabled of ns %s from %s to %s", ns->name, bool_val[ns->ldt_enabled], context);
				ns->ldt_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of ldt-enabled of ns %s from %s to %s", ns->name, bool_val[ns->ldt_enabled], context);
				ns->ldt_enabled = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "ldt-page-size", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
	  		if (val > ns->storage_write_block_size) {
				// 1Kb head room
				val = ns->storage_write_block_size - 1024;
			}
			cf_info(AS_INFO, "Changing value of ldt-page-size of ns %s from %d to %d ", ns->name, ns->ldt_page_size, val);
			ns->ldt_page_size = val;
		}
		else if (0 == as_info_parameter_get(params, "ldt-gc-rate", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			uint64_t rate = (uint64_t)val;

			if ((rate == 0) || (rate > LDT_SUB_GC_MAX_RATE)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of ldt-gc-rate of ns %s from %u to %d", ns->name, (1000 * 1000)/ns->ldt_gc_sleep_us , val);
			ns->ldt_gc_sleep_us = 1000 * 1000 / rate;
		}
		else if (0 == as_info_parameter_get(params, "defrag-lwm-pct", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of defrag-lwm-pct of ns %s from %d to %d ", ns->name, ns->storage_defrag_lwm_pct, val);

			uint32_t old_val = ns->storage_defrag_lwm_pct;

			ns->storage_defrag_lwm_pct = val;
			ns->defrag_lwm_size = (ns->storage_write_block_size * ns->storage_defrag_lwm_pct) / 100;

			if (ns->storage_defrag_lwm_pct > old_val) {
				as_storage_defrag_sweep(ns);
			}
		}
		else if (0 == as_info_parameter_get(params, "defrag-queue-min", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of defrag-queue-min of ns %s from %u to %d", ns->name, ns->storage_defrag_queue_min, val);
			ns->storage_defrag_queue_min = (uint32_t)val;
		}
		else if (0 == as_info_parameter_get(params, "defrag-sleep", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of defrag-sleep of ns %s from %u to %d", ns->name, ns->storage_defrag_sleep, val);
			ns->storage_defrag_sleep = (uint32_t)val;
		}
		else if (0 == as_info_parameter_get(params, "flush-max-ms", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of flush-max-ms of ns %s from %lu to %d", ns->name, ns->storage_flush_max_us / 1000, val);
			ns->storage_flush_max_us = (uint64_t)val * 1000;
		}
		else if (0 == as_info_parameter_get(params, "fsync-max-sec", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of fsync-max-sec of ns %s from %lu to %d", ns->name, ns->storage_fsync_max_us / 1000000, val);
			ns->storage_fsync_max_us = (uint64_t)val * 1000000;
		}
		else if (0 == as_info_parameter_get(params, "enable-xdr", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-xdr of ns %s from %s to %s", ns->name, bool_val[ns->enable_xdr], context);
				ns->enable_xdr = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-xdr of ns %s from %s to %s", ns->name, bool_val[ns->enable_xdr], context);
				ns->enable_xdr = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "sets-enable-xdr", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of sets-enable-xdr of ns %s from %s to %s", ns->name, bool_val[ns->sets_enable_xdr], context);
				ns->sets_enable_xdr = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of sets-enable-xdr of ns %s from %s to %s", ns->name, bool_val[ns->sets_enable_xdr], context);
				ns->sets_enable_xdr = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "ns-forward-xdr-writes", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of ns-forward-xdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_forward_xdr_writes], context);
				ns->ns_forward_xdr_writes = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of ns-forward-xdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_forward_xdr_writes], context);
				ns->ns_forward_xdr_writes = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "allow-nonxdr-writes", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of allow-nonxdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_allow_nonxdr_writes], context);
				ns->ns_allow_nonxdr_writes = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of allow-nonxdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_allow_nonxdr_writes], context);
				ns->ns_allow_nonxdr_writes = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "allow-xdr-writes", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of allow-xdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_allow_xdr_writes], context);
				ns->ns_allow_xdr_writes = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of allow-xdr-writes of ns %s from %s to %s", ns->name, bool_val[ns->ns_allow_xdr_writes], context);
				ns->ns_allow_xdr_writes = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "disallow-null-setname", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of disallow-null-setname of ns %s from %s to %s", ns->name, bool_val[ns->disallow_null_setname], context);
				ns->disallow_null_setname = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of disallow-null-setname of ns %s from %s to %s", ns->name, bool_val[ns->disallow_null_setname], context);
				ns->disallow_null_setname = false;
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-batch-sub", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-batch-sub of ns %s from %s to %s", ns->name, bool_val[ns->batch_sub_benchmarks_enabled], context);
				ns->batch_sub_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-batch-sub of ns %s from %s to %s", ns->name, bool_val[ns->batch_sub_benchmarks_enabled], context);
				ns->batch_sub_benchmarks_enabled = false;
				histogram_clear(ns->batch_sub_start_hist);
				histogram_clear(ns->batch_sub_restart_hist);
				histogram_clear(ns->batch_sub_dup_res_hist);
				histogram_clear(ns->batch_sub_read_local_hist);
				histogram_clear(ns->batch_sub_response_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-read", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-read of ns %s from %s to %s", ns->name, bool_val[ns->read_benchmarks_enabled], context);
				ns->read_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-read of ns %s from %s to %s", ns->name, bool_val[ns->read_benchmarks_enabled], context);
				ns->read_benchmarks_enabled = false;
				histogram_clear(ns->read_start_hist);
				histogram_clear(ns->read_restart_hist);
				histogram_clear(ns->read_dup_res_hist);
				histogram_clear(ns->read_local_hist);
				histogram_clear(ns->read_response_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-storage", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-storage of ns %s from %s to %s", ns->name, bool_val[ns->storage_benchmarks_enabled], context);
				ns->storage_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-storage of ns %s from %s to %s", ns->name, bool_val[ns->storage_benchmarks_enabled], context);
				ns->storage_benchmarks_enabled = false;
				as_storage_histogram_clear_all(ns);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-udf", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-udf of ns %s from %s to %s", ns->name, bool_val[ns->udf_benchmarks_enabled], context);
				ns->udf_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-udf of ns %s from %s to %s", ns->name, bool_val[ns->udf_benchmarks_enabled], context);
				ns->udf_benchmarks_enabled = false;
				histogram_clear(ns->udf_start_hist);
				histogram_clear(ns->udf_restart_hist);
				histogram_clear(ns->udf_dup_res_hist);
				histogram_clear(ns->udf_master_hist);
				histogram_clear(ns->udf_repl_write_hist);
				histogram_clear(ns->udf_response_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-udf-sub", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-udf-sub of ns %s from %s to %s", ns->name, bool_val[ns->udf_sub_benchmarks_enabled], context);
				ns->udf_sub_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-udf-sub of ns %s from %s to %s", ns->name, bool_val[ns->udf_sub_benchmarks_enabled], context);
				ns->udf_sub_benchmarks_enabled = false;
				histogram_clear(ns->udf_sub_start_hist);
				histogram_clear(ns->udf_sub_restart_hist);
				histogram_clear(ns->udf_sub_dup_res_hist);
				histogram_clear(ns->udf_sub_master_hist);
				histogram_clear(ns->udf_sub_repl_write_hist);
				histogram_clear(ns->udf_sub_response_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-benchmarks-write", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-write of ns %s from %s to %s", ns->name, bool_val[ns->write_benchmarks_enabled], context);
				ns->write_benchmarks_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-benchmarks-write of ns %s from %s to %s", ns->name, bool_val[ns->write_benchmarks_enabled], context);
				ns->write_benchmarks_enabled = false;
				histogram_clear(ns->write_start_hist);
				histogram_clear(ns->write_restart_hist);
				histogram_clear(ns->write_dup_res_hist);
				histogram_clear(ns->write_master_hist);
				histogram_clear(ns->write_repl_write_hist);
				histogram_clear(ns->write_response_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "enable-hist-proxy", context, &context_len)) {
			if (strncmp(context, "true", 4) == 0 || strncmp(context, "yes", 3) == 0) {
				cf_info(AS_INFO, "Changing value of enable-hist-proxy of ns %s from %s to %s", ns->name, bool_val[ns->proxy_hist_enabled], context);
				ns->proxy_hist_enabled = true;
			}
			else if (strncmp(context, "false", 5) == 0 || strncmp(context, "no", 2) == 0) {
				cf_info(AS_INFO, "Changing value of enable-hist-proxy of ns %s from %s to %s", ns->name, bool_val[ns->proxy_hist_enabled], context);
				ns->proxy_hist_enabled = false;
				histogram_clear(ns->proxy_hist);
			}
			else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "max-write-cache", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				goto Error;
			}
			if (val < (1024 * 1024 * 4)) {
				cf_warning(AS_INFO, "can't set max-write-cache less than 4M");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of max-write-cache of ns %s from %lu to %d ", ns->name, ns->storage_max_write_cache, val);
			ns->storage_max_write_cache = (uint64_t)val;
			ns->storage_max_write_q = (int)(ns->storage_max_write_cache / ns->storage_write_block_size);
		}
		else if (0 == as_info_parameter_get(params, "min-avail-pct", context, &context_len)) {
			ns->storage_min_avail_pct = atoi(context);
			cf_info(AS_INFO, "Changing value of min-avail-pct of ns %s from %u to %u ", ns->name, ns->storage_min_avail_pct, atoi(context));
		}
		else if (0 == as_info_parameter_get(params, "post-write-queue", context, &context_len)) {
			if (ns->storage_data_in_memory) {
				cf_warning(AS_INFO, "ns %s, can't set post-write-queue if data-in-memory", ns->name);
				goto Error;
			}
			if (0 != cf_str_atoi(context, &val)) {
				cf_warning(AS_INFO, "ns %s, post-write-queue %s is not a number", ns->name, context);
				goto Error;
			}
			if ((uint32_t)val > (2 * 1024)) {
				cf_warning(AS_INFO, "ns %s, post-write-queue %u must be < 2K", ns->name, val);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of post-write-queue of ns %s from %d to %d ", ns->name, ns->storage_post_write_queue, val);
			cf_atomic32_set(&ns->storage_post_write_queue, (uint32_t)val);
		}
		else if (0 == as_info_parameter_get(params, "sindex-data-max-memory", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_debug(AS_INFO, "sindex-data-max-memory = %"PRIu64"", val);
			if (val > ns->sindex_data_max_memory)
				ns->sindex_data_max_memory = val;
			if (val < (ns->sindex_data_max_memory / 2L)) { // protect so someone does not reduce memory to below 1/2 current value
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of sindex-data-max-memory of ns %s from %"PRIu64" to %"PRIu64, ns->name, ns->sindex_data_max_memory, val);
			ns->sindex_data_max_memory = val;
		}
		else if (0 == as_info_parameter_get(params, "indexname", context, &context_len)) {
			as_sindex_metadata imd;
			memset((void *)&imd, 0, sizeof(imd));
			imd.ns_name = cf_strdup(ns->name);
			imd.iname   = cf_strdup(context);
			int ret_val = as_sindex_set_config(ns, &imd, params);

			if (imd.ns_name) cf_free(imd.ns_name);
			if (imd.iname) cf_free(imd.iname);

			if (ret_val) {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "read-consistency-level-override", context, &context_len)) {
			char *original_value = NS_READ_CONSISTENCY_LEVEL_NAME();
			if (strcmp(context, "all") == 0) {
				ns->read_consistency_level = AS_POLICY_CONSISTENCY_LEVEL_ALL;
				ns->read_consistency_level_override = true;
			}
			else if (strcmp(context, "off") == 0) {
				ns->read_consistency_level = AS_POLICY_CONSISTENCY_LEVEL_ONE; // restore default
				ns->read_consistency_level_override = false;
			}
			else if (strcmp(context, "one") == 0) {
				ns->read_consistency_level = AS_POLICY_CONSISTENCY_LEVEL_ONE;
				ns->read_consistency_level_override = true;
			}
			else {
				goto Error;
			}
			if (strcmp(original_value, context)) {
				cf_info(AS_INFO, "Changing value of read-consistency-level-override of ns %s from %s to %s", ns->name, original_value, context);
			}
		}
		else if (0 == as_info_parameter_get(params, "write-commit-level-override", context, &context_len)) {
			char *original_value = NS_WRITE_COMMIT_LEVEL_NAME();
			if (strcmp(context, "all") == 0) {
				ns->write_commit_level = AS_POLICY_COMMIT_LEVEL_ALL;
				ns->write_commit_level_override = true;
			}
			else if (strcmp(context, "master") == 0) {
				ns->write_commit_level = AS_POLICY_COMMIT_LEVEL_MASTER;
				ns->write_commit_level_override = true;
			}
			else if (strcmp(context, "off") == 0) {
				ns->write_commit_level = AS_POLICY_COMMIT_LEVEL_ALL; // restore default
				ns->write_commit_level_override = false;
			}
			else {
				goto Error;
			}
			if (strcmp(original_value, context)) {
				cf_info(AS_INFO, "Changing value of write-commit-level-override of ns %s from %s to %s", ns->name, original_value, context);
			}
		}
		else if (0 == as_info_parameter_get(params, "geo2dsphere-within-max-cells", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val)) {
				cf_warning(AS_INFO, "ns %s, geo2dsphere-within-max-cells %s is not a number", ns->name, context);
				goto Error;
			}
			if (val <= 0) {
				cf_warning(AS_INFO, "ns %s, geo2dsphere-within-max-cells %u must be > 0", ns->name, val);
				goto Error;
			}
			if ((uint32_t)val > (MAX_REGION_CELLS)) {
				cf_warning(AS_INFO, "ns %s, geo2dsphere-within-max-cells %u must be <= %u", ns->name, val, MAX_REGION_CELLS);
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of geo2dsphere-within-max-cells of ns %s from %d to %d ",
					ns->name, ns->geo2dsphere_within_max_cells, val);
			ns->geo2dsphere_within_max_cells = val;
		}
		else if (0 == as_xdr_set_config_ns(ns->name, params)) {
			;
		}
		else {
			goto Error;
		}
	} // end of namespace stanza
	else if (strcmp(context, "security") == 0) {
		context_len = sizeof(context);
		if (0 == as_info_parameter_get(params, "privilege-refresh-period", context, &context_len)) {
			if (0 != cf_str_atoi(context, &val) || val < 10 || val > 60 * 60 * 24) {
				cf_warning(AS_INFO, "privilege-refresh-period must be an unsigned integer between 10 and 86400");
				goto Error;
			}
			cf_info(AS_INFO, "Changing value of privilege-refresh-period from %u to %d", g_config.sec_cfg.privilege_refresh_period, val);
			g_config.sec_cfg.privilege_refresh_period = (uint32_t)val;
		}
		else {
			goto Error;
		}
	}
	else if (strcmp(context, "xdr") == 0) {
		context_len = sizeof(context);
		if (0 == as_info_parameter_get(params, "lastshiptime", context, &context_len)) {
			// Dont print this command in logs as this happens every few seconds
			// Ideally, this should not be done via config-set.
			print_command = false;

			uint64_t val[DC_MAX_NUM];
			char * tmp_val;
			char *  delim = {","};
			int i = 0;

			// We do not want junk values in val[]. This is LST array.
			// Not doing that will lead to wrong LST time going back warnings from the code below.
			memset(val, 0, sizeof(uint64_t) * DC_MAX_NUM);

			tmp_val = strtok(context, (const char *) delim);
			while(tmp_val) {
				if(i >= DC_MAX_NUM) {
					cf_warning(AS_INFO, "Suspicious \"xdr\" Info command \"lastshiptime\" value: \"%s\"", params);
					break;
				}
				if (0 > cf_str_atoi_u64(tmp_val, &(val[i++]))) {
					cf_warning(AS_INFO, "bad number in \"xdr\" Info command \"lastshiptime\": \"%s\" for DC %d ~~ Using 0", tmp_val, i - 1);
					val[i - 1] = 0;
				}
				tmp_val = strtok(NULL, (const char *) delim);
			}

			for(i = 0; i < DC_MAX_NUM; i++) {
				// Warning only if time went back by 5 mins or more
				// We are doing subtraction of two uint64_t here. We should be more careful and first check
				// if the first value is greater.
				if ((g_config.xdr_self_lastshiptime[i] > val[i]) &&
						((g_config.xdr_self_lastshiptime[i] - val[i]) > XDR_ACCEPTABLE_TIMEDIFF)) {
					cf_warning(AS_INFO, "XDR last ship time of this node for DC %d went back to %"PRIu64" from %"PRIu64"",
							i, val[i], g_config.xdr_self_lastshiptime[i]);
					cf_debug(AS_INFO, "(Suspicious \"xdr\" Info command \"lastshiptime\" value: \"%s\".)", params);
				}

				g_config.xdr_self_lastshiptime[i] = val[i];
			}

			xdr_broadcast_lastshipinfo(val);
		}
		else if (0 == as_info_parameter_get(params, "failednodeprocessingdone", context, &context_len)) {
			print_command = false;
			cf_node nodeid = atoll(context);
			xdr_handle_failednodeprocessingdone(nodeid);
		}
		else {
			as_xdr_set_config(params, db);
			return 0;
		}
	}
	else
		goto Error;

	if (print_command) {
		cf_info(AS_INFO, "config-set command completed: params %s",params);
	}
	cf_dyn_buf_append_string(db, "ok");
	return(0);

Error:
	cf_dyn_buf_append_string(db, "error");
	return(0);
}

//
// log-set:log=id;context=foo;level=bar
// ie:
//   log-set:log=0;context=rw;level=debug


int
info_command_log_set(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "log-set command received: params %s", params);

	char id_str[50];
	int  id_str_len = sizeof(id_str);
	int  id = -1;
	bool found_id = true;
	cf_fault_sink *s = 0;

	if (0 != as_info_parameter_get(params, "id", id_str, &id_str_len)) {
		if (0 != as_info_parameter_get(params, "log", id_str, &id_str_len)) {
			cf_debug(AS_INFO, "log set command: no log id to be set - doing all");
			found_id = false;
		}
	}
	if (found_id == true) {
		if (0 != cf_str_atoi(id_str, &id) ) {
			cf_info(AS_INFO, "log set command: id must be an integer, is: %s", id_str);
			cf_dyn_buf_append_string(db, "error-id-not-integer");
			return(0);
		}
		s = cf_fault_sink_get_id(id);
		if (!s) {
			cf_info(AS_INFO, "log set command: sink id %d invalid", id);
			cf_dyn_buf_append_string(db, "error-bad-id");
			return(0);
		}
	}

	// now, loop through all context strings. If we find a known context string,
	// do the set
	for (int c_id = 0; c_id < CF_FAULT_CONTEXT_UNDEF; c_id++) {

		char level_str[50];
		int  level_str_len = sizeof(level_str);
		char *context = cf_fault_context_strings[c_id];
		if (0 != as_info_parameter_get(params, context, level_str, &level_str_len)) {
			continue;
		}
		for (uint i = 0; level_str[i]; i++) level_str[i] = toupper(level_str[i]);

		if (0 != cf_fault_sink_addcontext(s, context, level_str)) {
			cf_info(AS_INFO, "log set command: addcontext failed: context %s level %s", context, level_str);
			cf_dyn_buf_append_string(db, "error-invalid-context-or-level");
			return(0);
		}
	}

	cf_info(AS_INFO, "log-set command executed: params %s", params);

	cf_dyn_buf_append_string(db, "ok");

	return(0);
}


// latency:hist=reads;back=180;duration=60;slice=10;
// throughput:hist=reads;back=180;duration=60;slice=10;
// hist-track-start:hist=reads;back=43200;slice=30;thresholds=1,4,16,64;
// hist-track-stop:hist=reads;
//
// hist     - optional histogram name - if none, command applies to all cf_hist_track objects
//
// for start command:
// back     - total time span in seconds over which to cache data
// slice    - period in seconds at which to cache histogram data
// thresholds - comma-separated bucket (ms) values to track, must be powers of 2. e.g:
//				1,4,16,64
// defaults are:
// - config value for back - mandatory, serves as flag for tracking
// - config value if it exists for slice, otherwise 10 seconds
// - config value if it exists for thresholds, otherwise internal defaults (1,8,64)
//
// for query commands:
// back     - start search this many seconds before now, default: minimum to get last slice
//			  using back=0 will get cached data from oldest cached data
// duration - seconds (forward) from start to search, default 0: everything to present
// slice    - intervals (in seconds) to analyze, default 0: everything as one slice
//
// e.g. query:
// latency:hist=reads;back=180;duration=60;slice=10;
// output (CF_HIST_TRACK_FMT_PACKED format) is:
// requested value  latency:hist=reads;back=180;duration=60;slice=10
// value is  reads:23:26:24-GMT,ops/sec,>1ms,>8ms,>64ms;23:26:34,30618.2,0.05,0.00,0.00;
// 23:26:44,31942.1,0.02,0.00,0.00;23:26:54,30966.9,0.01,0.00,0.00;23:27:04,30380.4,0.01,0.00,0.00;
// 23:27:14,37833.6,0.01,0.00,0.00;23:27:24,38502.7,0.01,0.00,0.00;23:27:34,39191.4,0.02,0.00,0.00;
//
// explanation:
// 23:26:24-GMT - timestamp of histogram starting first slice
// ops/sec,>1ms,>8ms,>64ms - labels for the columns: throughput, and which thresholds
// 23:26:34,30618.2,0.05,0.00,0.00; - timestamp of histogram ending slice, throughput, latencies

int
info_command_hist_track(char *name, char *params, cf_dyn_buf *db)
{
	cf_debug(AS_INFO, "hist track %s command received: params %s", name, params);

	char value_str[50];
	int  value_str_len = sizeof(value_str);
	cf_hist_track* hist_p = NULL;

	if (0 != as_info_parameter_get(params, "hist", value_str, &value_str_len)) {
		cf_debug(AS_INFO, "hist track %s command: no histogram specified - doing all", name);
	}
	else {
		if (*value_str == '{') {
			char* ns_name = value_str + 1;
			char* ns_name_end = strchr(ns_name, '}');
			as_namespace* ns = as_namespace_get_bybuf((uint8_t*)ns_name, ns_name_end - ns_name);

			if (! ns) {
				cf_info(AS_INFO, "hist track %s command: unrecognized histogram: %s", name, value_str);
				cf_dyn_buf_append_string(db, "error-bad-hist-name");
				return 0;
			}

			char* hist_name = ns_name_end + 1;

			if (*hist_name++ != '-') {
				cf_info(AS_INFO, "hist track %s command: unrecognized histogram: %s", name, value_str);
				cf_dyn_buf_append_string(db, "error-bad-hist-name");
				return 0;
			}

			if (0 == strcmp(hist_name, "read")) {
				hist_p = ns->read_hist;
			}
			else if (0 == strcmp(hist_name, "write")) {
				hist_p = ns->write_hist;
			}
			else if (0 == strcmp(hist_name, "udf")) {
				hist_p = ns->udf_hist;
			}
			else if (0 == strcmp(hist_name, "query")) {
				hist_p = ns->query_hist;
			}
			else {
				cf_info(AS_INFO, "hist track %s command: unrecognized histogram: %s", name, value_str);
				cf_dyn_buf_append_string(db, "error-bad-hist-name");
				return 0;
			}
		}
		else {
			cf_info(AS_INFO, "hist track %s command: unrecognized histogram: %s", name, value_str);
			cf_dyn_buf_append_string(db, "error-bad-hist-name");
			return 0;
		}
	}

	if (0 == strcmp(name, "hist-track-stop")) {
		if (hist_p) {
			cf_hist_track_stop(hist_p);
		}
		else {
			for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
				as_namespace* ns = g_config.namespaces[i];

				cf_hist_track_stop(ns->read_hist);
				cf_hist_track_stop(ns->write_hist);
				cf_hist_track_stop(ns->udf_hist);
				cf_hist_track_stop(ns->query_hist);
			}
		}

		cf_dyn_buf_append_string(db, "ok");

		return 0;
	}

	bool start_cmd = 0 == strcmp(name, "hist-track-start");

	// Note - default query params will get the most recent saved slice.
	uint32_t back_sec = start_cmd ? g_config.hist_track_back : (g_config.hist_track_slice * 2) - 1;
	uint32_t slice_sec = start_cmd ? g_config.hist_track_slice : 0;
	int i;

	value_str_len = sizeof(value_str);

	if (0 == as_info_parameter_get(params, "back", value_str, &value_str_len)) {
		if (0 == cf_str_atoi(value_str, &i)) {
			back_sec = i >= 0 ? (uint32_t)i : (uint32_t)-i;
		}
		else {
			cf_info(AS_INFO, "hist track %s command: back is not a number, using default", name);
		}
	}

	value_str_len = sizeof(value_str);

	if (0 == as_info_parameter_get(params, "slice", value_str, &value_str_len)) {
		if (0 == cf_str_atoi(value_str, &i)) {
			slice_sec = i >= 0 ? (uint32_t)i : (uint32_t)-i;
		}
		else {
			cf_info(AS_INFO, "hist track %s command: slice is not a number, using default", name);
		}
	}

	if (start_cmd) {
		char* thresholds = g_config.hist_track_thresholds;

		value_str_len = sizeof(value_str);

		if (0 == as_info_parameter_get(params, "thresholds", value_str, &value_str_len)) {
			thresholds = value_str;
		}

		cf_debug(AS_INFO, "hist track start command: back %u, slice %u, thresholds %s",
				back_sec, slice_sec, thresholds ? thresholds : "null");

		if (hist_p) {
			if (cf_hist_track_start(hist_p, back_sec, slice_sec, thresholds)) {
				cf_dyn_buf_append_string(db, "ok");
			}
			else {
				cf_dyn_buf_append_string(db, "error-bad-start-params");
			}
		}
		else {
			for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
				as_namespace* ns = g_config.namespaces[i];

				if ( ! (cf_hist_track_start(ns->read_hist, back_sec, slice_sec, thresholds) &&
						cf_hist_track_start(ns->write_hist, back_sec, slice_sec, thresholds) &&
						cf_hist_track_start(ns->udf_hist, back_sec, slice_sec, thresholds) &&
						cf_hist_track_start(ns->query_hist, back_sec, slice_sec, thresholds))) {

					cf_dyn_buf_append_string(db, "error-bad-start-params");
					return 0;
				}
			}

			cf_dyn_buf_append_string(db, "ok");
		}

		return 0;
	}

	// From here on it's latency or throughput...

	uint32_t duration_sec = 0;

	value_str_len = sizeof(value_str);

	if (0 == as_info_parameter_get(params, "duration", value_str, &value_str_len)) {
		if (0 == cf_str_atoi(value_str, &i)) {
			duration_sec = i >= 0 ? (uint32_t)i : (uint32_t)-i;
		}
		else {
			cf_info(AS_INFO, "hist track %s command: duration is not a number, using default", name);
		}
	}

	bool throughput_only = 0 == strcmp(name, "throughput");

	cf_debug(AS_INFO, "hist track %s command: back %u, duration %u, slice %u",
			name, back_sec, duration_sec, slice_sec);

	if (hist_p) {
		cf_hist_track_get_info(hist_p, back_sec, duration_sec, slice_sec, throughput_only, CF_HIST_TRACK_FMT_PACKED, db);
	}
	else {
		for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
			as_namespace* ns = g_config.namespaces[i];

			cf_hist_track_get_info(ns->read_hist, back_sec, duration_sec, slice_sec, throughput_only, CF_HIST_TRACK_FMT_PACKED, db);
			cf_hist_track_get_info(ns->write_hist, back_sec, duration_sec, slice_sec, throughput_only, CF_HIST_TRACK_FMT_PACKED, db);
			cf_hist_track_get_info(ns->udf_hist, back_sec, duration_sec, slice_sec, throughput_only, CF_HIST_TRACK_FMT_PACKED, db);
			cf_hist_track_get_info(ns->query_hist, back_sec, duration_sec, slice_sec, throughput_only, CF_HIST_TRACK_FMT_PACKED, db);
		}
	}

	cf_dyn_buf_chomp(db);

	return 0;
}

//
// Log a message to the server.
// Limited to 2048 characters.
//
// Format:
//	log-message:message=<MESSAGE>[;who=<WHO>]
//
// Example:
// 	log-message:message=Example Log Message;who=Aerospike User
//
int
info_command_log_message(char *name, char *params, cf_dyn_buf *db)
{
	char who[128];
	int who_len = sizeof(who);
	if (0 != as_info_parameter_get(params, "who", who, &who_len)) {
		strcpy(who, "unknown");
	}

	char message[2048];
	int message_len = sizeof(message);
	if (0 == as_info_parameter_get(params, "message", message, &message_len)) {
		cf_info(AS_INFO, "%s: %s", who, message);
	}

	return 0;
}

// Generic info system functions
// These functions act when an INFO message comes in over the PROTO pipe
// collects the static and dynamic portions, puts it in a 'dyn buf',
// and sends a reply
//

// Error strings for security check results.
static void
append_sec_err_str(cf_dyn_buf *db, uint32_t result, as_sec_perm cmd_perm) {
	switch (result) {
	case AS_SEC_ERR_NOT_AUTHENTICATED:
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_uint32(db, result);
		cf_dyn_buf_append_string(db, ":not authenticated");
		return;
	case AS_SEC_ERR_ROLE_VIOLATION:
		switch (cmd_perm) {
		case PERM_INDEX_MANAGE:
			INFO_COMMAND_SINDEX_FAILCODE(result, "role violation");
			return;
		case PERM_UDF_MANAGE:
			cf_dyn_buf_append_string(db, "error=role_violation");
			return;
		default:
			break;
		}
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_uint32(db, result);
		cf_dyn_buf_append_string(db, ":role violation");
		return;
	default:
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_uint32(db, result);
		cf_dyn_buf_append_string(db, ":unexpected security error");
		return;
	}
}

static pthread_mutex_t		g_info_lock = PTHREAD_MUTEX_INITIALIZER;
info_static		*static_head = 0;
info_dynamic	*dynamic_head = 0;
info_tree		*tree_head = 0;
info_command	*command_head = 0;
//
// Pull up all elements in both list into the buffers
// (efficient enough if you're looking for lots of things)
// But only gets 'default' values
//

int
info_all(const as_file_handle* fd_h, cf_dyn_buf *db)
{
	uint8_t auth_result = as_security_check(fd_h, PERM_NONE);

	if (auth_result != AS_PROTO_RESULT_OK) {
		as_security_log(fd_h, auth_result, PERM_NONE, "info-all request", NULL);
		append_sec_err_str(db, auth_result, PERM_NONE);
		cf_dyn_buf_append_char(db, EOL);
		return 0;
	}

	info_static *s = static_head;
	while (s) {
		if (s->def == true) {
			cf_dyn_buf_append_string( db, s->name);
			cf_dyn_buf_append_char( db, SEP );
			cf_dyn_buf_append_buf( db, (uint8_t *) s->value, s->value_sz);
			cf_dyn_buf_append_char( db, EOL );
		}
		s = s->next;
	}

	info_dynamic *d = dynamic_head;
	while (d) {
		if (d->def == true) {
			cf_dyn_buf_append_string( db, d->name);
			cf_dyn_buf_append_char(db, SEP );
			d->value_fn(d->name, db);
			cf_dyn_buf_append_char(db, EOL);
		}
		d = d->next;
	}

	return(0);
}

//
// Parse the input buffer. It contains a list of keys that should be spit back.
// Do the parse, call the necessary function collecting the information in question
// Filling the dynbuf

int
info_some(char *buf, char *buf_lim, const as_file_handle* fd_h, cf_dyn_buf *db)
{
	uint8_t auth_result = as_security_check(fd_h, PERM_NONE);

	if (auth_result != AS_PROTO_RESULT_OK) {
		// TODO - log null-terminated buf as detail?
		as_security_log(fd_h, auth_result, PERM_NONE, "info request", NULL);
		append_sec_err_str(db, auth_result, PERM_NONE);
		cf_dyn_buf_append_char(db, EOL);
		return 0;
	}

	// For each incoming name
	char	*c = buf;
	char	*tok = c;

	while (c < buf_lim) {

		if ( *c == EOL ) {
			*c = 0;
			char *name = tok;
			bool handled = false;

			// search the static queue first always
			info_static *s = static_head;
			while (s) {
				if (strcmp(s->name, name) == 0) {
					// return exact command string received from client
					cf_dyn_buf_append_string( db, name);
					cf_dyn_buf_append_char( db, SEP );
					cf_dyn_buf_append_buf( db, (uint8_t *) s->value, s->value_sz);
					cf_dyn_buf_append_char( db, EOL );
					handled = true;
					break;
				}
				s = s->next;
			}

			// didn't find in static, try dynamic
			if (!handled) {
				info_dynamic *d = dynamic_head;
				while (d) {
					if (strcmp(d->name, name) == 0) {
						// return exact command string received from client
						cf_dyn_buf_append_string( db, d->name);
						cf_dyn_buf_append_char(db, SEP );
						d->value_fn(d->name, db);
						cf_dyn_buf_append_char(db, EOL);
						handled = true;
						break;
					}
					d = d->next;
				}
			}

			// search the tree
			if (!handled) {

				// see if there's a '/',
				char *branch = strchr( name, TREE_SEP);
				if (branch) {
					*branch = 0;
					branch++;

					info_tree *t = tree_head;
					while (t) {
						if (strcmp(t->name, name) == 0) {
							// return exact command string received from client
							cf_dyn_buf_append_string( db, t->name);
							cf_dyn_buf_append_char( db, TREE_SEP);
							cf_dyn_buf_append_string( db, branch);
							cf_dyn_buf_append_char(db, SEP );
							t->tree_fn(t->name, branch, db);
							cf_dyn_buf_append_char(db, EOL);
							handled = true;
							break;
						}
						t = t->next;
					}
				}
			}

			tok = c + 1;
		}
		// commands have parameters
		else if ( *c == ':' ) {
			*c = 0;
			char *name = tok;

			// parse parameters
			tok = c + 1;
			// make sure c doesn't go beyond buf_lim
			while (*c != EOL && c < buf_lim-1) c++;
			if (*c != EOL) {
				cf_warning(AS_INFO, "Info '%s' parameter not terminated with '\\n'.", name);
				break;
			}
			*c = 0;
			char *param = tok;

			// search the command list
			info_command *cmd = command_head;
			while (cmd) {
				if (strcmp(cmd->name, name) == 0) {
					// return exact command string received from client
					cf_dyn_buf_append_string( db, name);
					cf_dyn_buf_append_char( db, ':');
					cf_dyn_buf_append_string( db, param);
					cf_dyn_buf_append_char( db, SEP );

					uint8_t result = as_security_check(fd_h, cmd->required_perm);

					as_security_log(fd_h, result, cmd->required_perm, name, param);

					if (result == AS_PROTO_RESULT_OK) {
						cmd->command_fn(cmd->name, param, db);
					}
					else {
						append_sec_err_str(db, result, cmd->required_perm);
					}

					cf_dyn_buf_append_char( db, EOL );
					break;
				}
				cmd = cmd->next;
			}

			if (!cmd) {
				cf_info(AS_INFO, "received command %s, not registered", name);
			}

			tok = c + 1;
		}

		c++;

	}
	return(0);
}

int
as_info_buffer(uint8_t *req_buf, size_t req_buf_len, cf_dyn_buf *rsp)
{
	// Either we'e doing all, or doing some
	if (req_buf_len == 0) {
		info_all(NULL, rsp);
	}
	else {
		info_some((char *)req_buf, (char *)(req_buf + req_buf_len), NULL, rsp);
	}

	return(0);
}

//
// Worker threads!
// these actually do the work. There is a lot of network activity,
// writes and such, don't want to clog up the main queue
//

void *
thr_info_fn(void *unused)
{
	for ( ; ; ) {

		as_info_transaction it;

		if (0 != cf_queue_pop(g_info_work_q, &it, CF_QUEUE_FOREVER)) {
			cf_crash(AS_TSVC, "unable to pop from info work queue");
		}

		as_file_handle *fd_h = it.fd_h;
		as_proto *pr = it.proto;

		// Allocate an output buffer sufficiently large to avoid ever resizing
		cf_dyn_buf_define_size(db, 128 * 1024);
		// write space for the header
		uint64_t	h = 0;
		cf_dyn_buf_append_buf(&db, (uint8_t *) &h, sizeof(h));

		// Either we'e doing all, or doing some
		if (pr->sz == 0) {
			info_all(fd_h, &db);
		}
		else {
			info_some((char *)pr->data, (char *)pr->data + pr->sz, fd_h, &db);
		}

		// write the proto header in the space we pre-wrote
		db.buf[0] = 2;
		db.buf[1] = 1;
		uint64_t	sz = db.used_sz - 8;
		db.buf[4] = (sz >> 24) & 0xff;
		db.buf[5] = (sz >> 16) & 0xff;
		db.buf[6] = (sz >> 8) & 0xff;
		db.buf[7] = sz & 0xff;

		// write the data buffer
		uint8_t	*b = db.buf;
		uint8_t	*lim = db.buf + db.used_sz;
		while (b < lim) {
			int rv = cf_socket_send(fd_h->sock, b, lim - b, MSG_NOSIGNAL);
			if ((rv < 0) && (errno != EAGAIN) ) {
				if (errno == EPIPE) {
					cf_debug(AS_INFO, "thr_info: client request gave up while I was processing: fd %d", CSFD(fd_h->sock));
				} else {
					cf_info(AS_INFO, "thr_info: can't write all bytes, fd %d error %d", CSFD(fd_h->sock), errno);
				}
				as_end_of_transaction_force_close(fd_h);
				fd_h = NULL;
				break;
			}
			else if (rv > 0)
				b += rv;
			else
				usleep(1);
		}

		cf_dyn_buf_free(&db);

		cf_free(pr);

		if (fd_h) {
			as_end_of_transaction_ok(fd_h);
			fd_h = NULL;
		}

		G_HIST_INSERT_DATA_POINT(info_hist, it.start_time);
		cf_atomic64_incr(&g_stats.info_complete);
	}

	return NULL;
}

//
// received an info request from a file descriptor
// Called by the thr_tsvc when an info message is seen
// calls functions info_all or info_some to collect the response
// calls write to send the response back
//
// Proto will be freed by the caller
//

void
as_info(as_info_transaction *it)
{
	if (0 != cf_queue_push(g_info_work_q, it)) {
		cf_warning(AS_INFO, "failed info queue push");

		// TODO - bother "handling" this?
		as_end_of_transaction_force_close(it->fd_h);
		cf_free(it->proto);
	}
}

// Return the number of pending Info requests in the queue.
int
as_info_queue_get_size()
{
	return cf_queue_sz(g_info_work_q);
}

// Registers a dynamic name-value calculator.
// the get_value_fn will be called if a request comes in for this name.
// only does the registration!
// def means it's part of the default results - will get invoked for a blank info command (asinfo -v "")


int
as_info_set_dynamic(char *name, as_info_get_value_fn gv_fn, bool def)
{
	int rv = -1;
	pthread_mutex_lock(&g_info_lock);

	info_dynamic *e = dynamic_head;
	while (e) {
		if (strcmp(name, e->name) == 0) {
			e->value_fn = gv_fn;
			break;
		}

		e = e->next;
	}

	if (!e) {
		e = cf_malloc(sizeof(info_dynamic));
		if (!e) goto Cleanup;
		e->def = def;
		e->name = cf_strdup(name);
		if (!e->name) {
			cf_free(e);
			goto Cleanup;
		}
		e->value_fn = gv_fn;
		e->next = dynamic_head;
		dynamic_head = e;
	}
	rv = 0;
Cleanup:
	pthread_mutex_unlock(&g_info_lock);
	return(rv);
}


// Registers a tree-based name-value calculator.
// the get_value_fn will be called if a request comes in for this name.
// only does the registration!


int
as_info_set_tree(char *name, as_info_get_tree_fn gv_fn)
{
	int rv = -1;
	pthread_mutex_lock(&g_info_lock);

	info_tree *e = tree_head;
	while (e) {
		if (strcmp(name, e->name) == 0) {
			e->tree_fn = gv_fn;
			break;
		}

		e = e->next;
	}

	if (!e) {
		e = cf_malloc(sizeof(info_tree));
		if (!e) goto Cleanup;
		e->name = cf_strdup(name);
		if (!e->name) {
			cf_free(e);
			goto Cleanup;
		}
		e->tree_fn = gv_fn;
		e->next = tree_head;
		tree_head = e;
	}
	rv = 0;
Cleanup:
	pthread_mutex_unlock(&g_info_lock);
	return(rv);
}


// Registers a command handler
// the get_value_fn will be called if a request comes in for this name, and
// parameters will be passed in
// This function only does the registration!

int
as_info_set_command(char *name, as_info_command_fn command_fn, as_sec_perm required_perm)
{
	int rv = -1;
	pthread_mutex_lock(&g_info_lock);

	info_command *e = command_head;
	while (e) {
		if (strcmp(name, e->name) == 0) {
			e->command_fn = command_fn;
			break;
		}

		e = e->next;
	}

	if (!e) {
		e = cf_malloc(sizeof(info_command));
		if (!e) goto Cleanup;
		e->name = cf_strdup(name);
		if (!e->name) {
			cf_free(e);
			goto Cleanup;
		}
		e->command_fn = command_fn;
		e->required_perm = required_perm;
		e->next = command_head;
		command_head = e;
	}
	rv = 0;
Cleanup:
	pthread_mutex_unlock(&g_info_lock);
	return(rv);
}



//
// Sets a static name-value pair
// def means it's part of the default set - will get returned if nothing is passed

int
as_info_set_buf(const char *name, const uint8_t *value, size_t value_sz, bool def)
{
	pthread_mutex_lock(&g_info_lock);

	// Delete case
	if (value_sz == 0 || value == 0) {

		info_static *p = 0;
		info_static *e = static_head;

		while (e) {
			if (strcmp(name, e->name) == 0) {
				if (p) {
					p->next = e->next;
					cf_free(e->name);
					cf_free(e->value);
					cf_free(e);
				}
				else {
					info_static *_t = static_head->next;
					cf_free(e->name);
					cf_free(e->value);
					cf_free(static_head);
					static_head = _t;
				}
				break;
			}
			p = e;
			e = e->next;
		}
	}
	// insert case
	else {

		info_static *e = static_head;

		// search for old value and overwrite
		while(e) {
			if (strcmp(name, e->name) == 0) {
				cf_free(e->value);
				e->value = cf_malloc(value_sz);
				memcpy(e->value, value, value_sz);
				e->value_sz = value_sz;
				break;
			}
			e = e->next;
		}

		// not found, insert fresh
		if (e == 0) {
			info_static *_t = cf_malloc(sizeof(info_static));
			_t->next = static_head;
			_t->def = def;
			_t->name = cf_strdup(name);
			_t->value = cf_malloc(value_sz);
			memcpy(_t->value, value, value_sz);
			_t->value_sz = value_sz;
			static_head = _t;
		}
	}

	pthread_mutex_unlock(&g_info_lock);
	return(0);

}

//
// A helper function. Commands have the form:
// cmd:param=value;param=value
//
// The main parser gives us the entire parameter string
// so use this function to scan through and get the particular parameter value
// you're looking for
//
// The 'param_string' is the param passed by the command parser into a command
//
// @return  0 : success
//         -1 : parameter not found
//         -2 : parameter found but value is too long
//

int
as_info_parameter_get(char *param_str, char *param, char *value, int *value_len)
{
	cf_detail(AS_INFO, "parameter get: paramstr %s seeking param %s", param_str, param);

	char *c = param_str;
	char *tok = param_str;
	int param_len = strlen(param);

	while (*c) {
		if (*c == '=') {
			if ( ( param_len == c - tok) && (0 == memcmp(tok, param, param_len) ) ) {
				c++;
				tok = c;
				while ( *c != 0 && *c != ';') c++;
				if (*value_len <= c - tok)	{
					// The found value is too long.
					return(-2);
				}
				*value_len = c - tok;
				memcpy(value, tok, *value_len);
				value[*value_len] = 0;
				return(0);
			}
			c++;
		}
		else if (*c == ';') {
			c++;
			tok = c;
		}
		else c++;

	}

	return(-1);
}

int
as_info_set(const char *name, const char *value, bool def)
{
	return(as_info_set_buf(name, (const uint8_t *) value, strlen(value), def ) );
}

//
//
// service interfaces management
//
// There's a worker thread - info_interfaces_fn ---
// which continually polls the interfaces to see if anything changed.
// When it changes, it updates a generation count.
// There's a hash table of all the other nodes in the cluster, and a counter
// to see that they're all up-to-date on the generation
//
//
// The fabric message in question can be expanded to do more than service interfaces.
// By expanding the 'info_node_info' structure, and the fabric_msg, you can carry
// more dynamic information than just the remote node's interfaces
// But that's all that we can think of at the moment - the paxos communication method
// makes sure that the distributed key system is properly distributed
//

static pthread_mutex_t		g_service_lock = PTHREAD_MUTEX_INITIALIZER;
char 		*g_service_str = 0;
uint32_t	g_service_generation = 0;

//
// What other nodes are out there, and what are their ip addresses?
//

typedef struct {
	uint64_t	last;				// last notice we got from a given node
	char 		*service_addr;		// string representing the service address
	char 		*alternate_addr;		// string representing the alternate address
	uint32_t	generation;			// acked generation counter
} info_node_info;

typedef struct {
	bool		printed_element;	// Boolean flag to control printing of ';'
	cf_dyn_buf	*db;
} services_printer;


// To avoid the services bug, g_info_node_info_hash should *always* be a subset
// of g_info_node_info_history_hash. In order to ensure this, every modification
// of g_info_node_info_hash should first involve grabbing the lock for the same
// key in g_info_node_info_history_hash.
shash *g_info_node_info_history_hash = 0;
shash *g_info_node_info_hash = 0;

int info_node_info_reduce_fn(void *key, void *data, void *udata);

void
build_service_list(cf_ip_addr *addrs, int32_t n_addrs, cf_dyn_buf *db) {
	bool empty = true;

	for (int32_t i = 0; i < n_addrs; ++i) {
		if (cf_ip_addr_is_loopback(&addrs[i])) {
			continue;
		}

		cf_sock_addr tmp;
		cf_sock_addr_from_addr_port(&addrs[i], g_config.socket.port, &tmp);
		cf_dyn_buf_append_string(db, cf_sock_addr_print(&tmp));
		cf_dyn_buf_append_char(db, ';');
		empty = false;
	}

	if (!empty) {
		cf_dyn_buf_chomp(db);
	}
}

//
// Note: if all my interfaces go down, service_str will be 0
//

static int32_t
inter_comp(const void *lhs, const void *rhs)
{
	return cf_ip_addr_compare(lhs, rhs);
}

void *
info_interfaces_fn(void *unused)
{
	cf_ip_addr known[100];
	int32_t n_known = 0;

	while (true) {
		uint8_t buffer[1000];
		cf_ip_addr *curr;
		int32_t n_curr;

		if (cf_inter_get_addr(&curr, &n_curr, buffer, sizeof(buffer)) < 0) {
			cf_crash(AS_CFG, "Error while getting interface addresses");
		}

		qsort(curr, n_curr, sizeof(cf_ip_addr), inter_comp);
		bool change = false;

		if (n_curr != n_known) {
			change = true;
		}
		else {
			for (int32_t i = 0; i < n_curr; ++i) {
				if (inter_comp(&known[i], &curr[i]) != 0) {
					change = true;
					break;
				}
			}
		}

		if (change) {
			cf_dyn_buf_define(services);
			build_service_list(curr, n_curr, &services);

			pthread_mutex_lock(&g_service_lock);

			if (g_service_str != NULL)
				cf_free(g_service_str);

			g_service_str = cf_dyn_buf_strdup(&services);
			g_service_generation++;

			pthread_mutex_unlock(&g_service_lock);
			cf_dyn_buf_free(&services);

			memcpy(known, curr, sizeof(cf_ip_addr) * n_curr);
			n_known = n_curr;
		}

		// reduce the info_node hash to apply any transmits
		shash_reduce(g_info_node_info_hash, info_node_info_reduce_fn, 0);
		sleep(2);
	}

	return NULL;
}

//
// pushes the external address to everyone in the fabric
//

void *
info_interfaces_static_fn(void *unused)
{

	cf_info(AS_INFO, " static external network definition ");

	// For valid external-address specify the same in service-list
	cf_dyn_buf_define(service_db);
	cf_dyn_buf_append_string(&service_db, g_config.external_address);
	cf_dyn_buf_append_char(&service_db, ':');
	cf_dyn_buf_append_int(&service_db, g_config.socket.port);

	pthread_mutex_lock(&g_service_lock);

	g_service_generation = 1;
	g_service_str = cf_dyn_buf_strdup(&service_db);

	pthread_mutex_unlock(&g_service_lock);

	cf_dyn_buf_free(&service_db);
	while (1) {

		// reduce the info_node hash to apply any transmits
		shash_reduce(g_info_node_info_hash, info_node_info_reduce_fn, 0);

		sleep(2);

	}
	return(0);
}

// This reduce function will eliminate elements from the info hash
// which are no longer in the succession list


int
info_paxos_event_reduce_fn(void *key, void *data, void *udata)
{
	cf_node		*node = (cf_node *) key;		// this is a single element
	cf_node		*succession = (cf_node *)	udata; // this is an array
	info_node_info *infop = (info_node_info *)data;

	uint i = 0;
	while (succession[i]) {
		if (*node == succession[i])
			break;
		i++;
	}

	if (succession[i] == 0) {
		cf_debug(AS_INFO, " paxos event reduce: removing node %"PRIx64, *node);
		if (infop->service_addr)    cf_free(infop->service_addr);
		if (infop->alternate_addr)    cf_free(infop->alternate_addr);
		return(SHASH_REDUCE_DELETE);
	}

	return(0);

}

//
// Maintain the info_node_info hash as a shadow of the succession list
//

void
as_info_paxos_event(as_paxos_generation gen, as_paxos_change *change, cf_node succession[], void *udata)
{

	uint64_t start_ms = cf_getms();

	cf_debug(AS_INFO, "info received new paxos state:");

	// Make sure all elements in the succession list are in the hash
	info_node_info info;
	info.last = 0;
	info.generation = 0;

	pthread_mutex_t *vlock_info_hash;
	info_node_info *infop_info_hash;

	pthread_mutex_t *vlock_info_history_hash;
	info_node_info *infop_info_history_hash;

	uint i = 0;
	while (succession[i]) {
		if (succession[i] != g_config.self_node) {

			info.service_addr = 0;
			info.alternate_addr = 0;

			// Get lock for info_history_hash
			if (SHASH_OK != shash_get_vlock(g_info_node_info_history_hash,
					&(succession[i]), (void **) &infop_info_history_hash,
					&vlock_info_history_hash)) {
				// Node not in info_history_hash, so add it.

				// This may fail, but this is ok. This should only fail when
				// info_msg_fn is also trying to add this key, so either
				// way the entry will be in the hash table.
				shash_put_unique(g_info_node_info_history_hash,
								 &(succession[i]), &info);

				if (SHASH_OK != shash_get_vlock(g_info_node_info_history_hash,
						&(succession[i]), (void **) &infop_info_history_hash,
						&vlock_info_history_hash)) {
					cf_assert(false, AS_INFO, CF_CRITICAL,
							"could not create info_history_hash entry for %"PRIx64, (succession[i]));
					continue;
				}
			}

			if (SHASH_OK != shash_get_vlock(g_info_node_info_hash, &(succession[i]),
					(void **) &infop_info_hash, &vlock_info_hash)) {
				if (infop_info_history_hash->service_addr) {
					// We remember the service address for this node!
					// Use this service address from info_history_hash in
					// the new entry into info_hash.
					cf_debug(AS_INFO, "info: from paxos notification: copying service address from info history hash for node %"PRIx64, succession[i]);
					info.service_addr = cf_strdup( infop_info_history_hash->service_addr );
					cf_assert(info.service_addr, AS_INFO, CF_CRITICAL, "malloc");
				}
				if (infop_info_history_hash->alternate_addr) {
					info.alternate_addr = cf_strdup( infop_info_history_hash->alternate_addr );
				}

				if (SHASH_OK == shash_put_unique(g_info_node_info_hash, &(succession[i]), &info)) {
					cf_debug(AS_INFO, "info: from paxos notification: inserted node %"PRIx64, succession[i]);
				} else {
					if (info.service_addr)	cf_free(info.service_addr);
					if (info.alternate_addr)	cf_free(info.alternate_addr);
					cf_assert(false, AS_INFO, CF_CRITICAL,
							"could not insert node %"PRIx64" from paxos notification",
							succession[i]);
				}
			} else {
				pthread_mutex_unlock(vlock_info_hash);
			}

			pthread_mutex_unlock(vlock_info_history_hash);
		}
		i++;
	}

	cf_debug(AS_INFO, "info: paxos succession list has %d elements. after insert, info hash has %d", i, shash_get_size(g_info_node_info_hash));

	// detect node deletion by reducing the hash table and deleting what needs deleting
	cf_debug(AS_INFO, "paxos event: try removing nodes");

	shash_reduce_delete(g_info_node_info_hash, info_paxos_event_reduce_fn, succession);

	cf_debug(AS_INFO, "info: after delete, info hash has %d", shash_get_size(g_info_node_info_hash));

	// probably, something changed in the list. Just ask the clients to update
	cf_atomic32_incr(&g_node_info_generation);

	cf_debug(AS_INFO, "as_info_paxos_event took %"PRIu64" ms", cf_getms() - start_ms);
}

// This goes in a reduce function for retransmitting my information to another node

int
info_node_info_reduce_fn(void *key, void *data, void *udata)
{
	cf_node *node = (cf_node *)key;
	info_node_info *infop = (info_node_info *) data;
	int rv;

	if (infop->generation < g_service_generation) {

		cf_debug(AS_INFO, "sending service string %s to node %"PRIx64, g_service_str, *node);

		pthread_mutex_lock(&g_service_lock);

		msg *m = as_fabric_msg_get(M_TYPE_INFO);
		if (0 == m) {
			cf_debug(AS_INFO, " could not get fabric message");
			return(-1);
		}

		// If we don't have the remote node's service address, request it via our update info. msg.
		msg_set_uint32(m, INFO_FIELD_OP, (infop->service_addr ? INFO_OP_UPDATE : INFO_OP_UPDATE_REQ));
		msg_set_uint32(m, INFO_FIELD_GENERATION, g_service_generation);
		if (g_service_str) {
			msg_set_str(m, INFO_FIELD_SERVICE_ADDRESS, g_service_str, MSG_SET_COPY);
		}
		if (g_config.alternate_address) {
			char alt_add_port[1024];
			snprintf(alt_add_port, 1024, "%s:%d", g_config.alternate_address, g_config.socket.port);
			msg_set_str(m, INFO_FIELD_ALT_ADDRESS, alt_add_port, MSG_SET_COPY);
		}

		pthread_mutex_unlock(&g_service_lock);

		if ((rv = as_fabric_send(*node, m, AS_FABRIC_PRIORITY_MEDIUM))) {
			as_fabric_msg_put(m);
		}
	}

	return(0);
}

//
// Receive a message from a remote node, jam it in my table
//


int
info_msg_fn(cf_node node, msg *m, void *udata)
{
	uint32_t op = 9999;
	msg_get_uint32(m, INFO_FIELD_OP, &op);
	int rv;

	switch (op) {
	case INFO_OP_UPDATE:
	case INFO_OP_UPDATE_REQ:
		{
			cf_debug(AS_INFO, " received service address from node %"PRIx64" ; op = %d", node, op);

			pthread_mutex_t *vlock_info_hash;
			info_node_info *infop_info_hash;

			pthread_mutex_t *vlock_info_history_hash;
			info_node_info *infop_info_history_hash;

			// Get lock for info_history_hash
			if (SHASH_OK != shash_get_vlock(g_info_node_info_history_hash, &node,
					(void **) &infop_info_history_hash, &vlock_info_history_hash)) {
				// Node not in info_history_hash, so add it.

				info_node_info info;
				info.last = 0;
				info.service_addr = 0;
				info.alternate_addr = 0;
				info.generation = 0;

				// This may fail, but this is ok. This should only fail when
				// as_info_paxos_event is also trying to add this key, so either
				// way the entry will be in the hash table.
				shash_put_unique(g_info_node_info_history_hash, &node, &info);

				if (SHASH_OK != shash_get_vlock(g_info_node_info_history_hash, &node,
						(void **) &infop_info_history_hash,
						&vlock_info_history_hash)) {
					cf_assert(false, AS_INFO, CF_CRITICAL,
							"could not create info_history_hash entry for %"PRIx64, node);
					break;
				}
			}

			if (infop_info_history_hash->service_addr) {
				cf_free(infop_info_history_hash->service_addr);
				infop_info_history_hash->service_addr = 0;
			}
			if (infop_info_history_hash->alternate_addr) {
				cf_free(infop_info_history_hash->alternate_addr);
				infop_info_history_hash->alternate_addr = 0;
			}

			if (0 != msg_get_str(m, INFO_FIELD_SERVICE_ADDRESS,
								 &(infop_info_history_hash->service_addr), 0,
								 MSG_GET_COPY_MALLOC)) {
				cf_warning(AS_INFO, "failed to get service address in an info msg from node %"PRIx64"", node);
				pthread_mutex_unlock(vlock_info_history_hash);
				break;
			}
			if (0 != msg_get_str(m, INFO_FIELD_ALT_ADDRESS,
								 &(infop_info_history_hash->alternate_addr), 0,
								 MSG_GET_COPY_MALLOC)) {
				cf_debug(AS_INFO, "failed to get alternate address in an info msg from node %"PRIx64"", node);
			}

			cf_debug(AS_INFO, " new service address is: %s", infop_info_history_hash->service_addr);
			cf_debug(AS_INFO, " new alternate address is: %s", infop_info_history_hash->alternate_addr ?
															infop_info_history_hash->alternate_addr : "NULL");

			// See if element is in info_hash
			// - if yes, update the service address.
			if (SHASH_OK == shash_get_vlock(g_info_node_info_hash, &node,
					(void **) &infop_info_hash, &vlock_info_hash)) {

				if (infop_info_hash->service_addr) {
					cf_free(infop_info_hash->service_addr);
					infop_info_hash->service_addr = 0;
				}
				if (infop_info_hash->alternate_addr) {
					cf_free(infop_info_hash->alternate_addr);
					infop_info_hash->alternate_addr = 0;
				}

				// Already unpacked msg in msg_get_str, so just copy the value
				// from infop_info_history_hash.
				if (!infop_info_history_hash->service_addr) {
					cf_warning(AS_INFO, "ignoring bad Info msg with NULL service_addr");
					pthread_mutex_unlock(vlock_info_hash);
					pthread_mutex_unlock(vlock_info_history_hash);
					break;
				}

				infop_info_hash->service_addr = cf_strdup( infop_info_history_hash->service_addr );
				infop_info_hash->alternate_addr = infop_info_history_hash->alternate_addr ?
												cf_strdup( infop_info_history_hash->alternate_addr ) : 0;
				cf_assert(infop_info_hash->service_addr, AS_INFO, CF_CRITICAL, "malloc");

				if (INFO_OP_UPDATE_REQ == op) {
					cf_debug(AS_INFO, "Received request for info update from node %"PRIx64" ~~ setting node's info generation to 0!", node);
					infop_info_hash->generation = 0;
				}

				pthread_mutex_unlock(vlock_info_hash);

			} else {
				// Before history_hash was added to code base, we would throw
				// away message in this case.
				cf_debug(AS_INFO, "node %"PRIx64" not in info_hash, saving service address in info_history_hash", node);
			}

			pthread_mutex_unlock(vlock_info_history_hash);

			// Send the ack.
			msg_preserve_fields(m, 1, INFO_FIELD_GENERATION);
			msg_set_uint32(m, INFO_FIELD_OP, INFO_OP_ACK);

			if ((rv = as_fabric_send(node, m, AS_FABRIC_PRIORITY_HIGH))) {
				cf_warning(AS_INFO, "failed to send msg %p type %d to node %"PRIu64" (rv %d)", m, m->type, node, rv);
				as_fabric_msg_put(m);
			}
		}
		break;

	case INFO_OP_ACK:
		{

			cf_debug(AS_INFO, " received ACK from node %"PRIx64, node);

			uint32_t	gen;
			msg_get_uint32(m, INFO_FIELD_GENERATION, &gen);
			info_node_info	*info;
			pthread_mutex_t	*vlock;
			if (0 == shash_get_vlock(g_info_node_info_hash, &node, (void **) &info, &vlock)) {

				info->generation = gen;

				pthread_mutex_unlock(vlock);
			}

			as_fabric_msg_put(m);

		}
		break;

	default:
		as_fabric_msg_put(m);
		break;
	}

	return(0);
}

//
// This dynamic function reduces the info_node_info hash and builds up the string of services
//

int
info_get_services_reduce_fn(void *key, void *data, void *udata)
{
	services_printer *sp = (services_printer *)udata;
	cf_dyn_buf *db = sp->db;
	info_node_info *infop = (info_node_info *) data;

	if (infop->service_addr) {
		if (sp->printed_element) {
			cf_dyn_buf_append_char(db, ';');
		}
		cf_dyn_buf_append_string(db, infop->service_addr);
		sp->printed_element = true;
	}

	return(0);
}

int
info_get_alt_addr_reduce_fn(void *key, void *data, void *udata)
{
	services_printer *sp = (services_printer *)udata;
	cf_dyn_buf *db = sp->db;
	info_node_info *infop = (info_node_info *) data;

	if (infop->alternate_addr) {
		if (sp->printed_element) {
			cf_dyn_buf_append_char(db, ';');
		}
		cf_dyn_buf_append_string(db, infop->alternate_addr);
		sp->printed_element = true;
	}

	return(0);
}

int
info_get_services(char *name, cf_dyn_buf *db)
{
	services_printer sp;
	sp.printed_element = false;
	sp.db = db;

	shash_reduce(g_info_node_info_hash, info_get_services_reduce_fn, (void *) &sp);

	return(0);
}

int
info_get_alt_addr(char *name, cf_dyn_buf *db)
{
	services_printer sp;
	sp.printed_element = false;
	sp.db = db;

	shash_reduce(g_info_node_info_hash, info_get_alt_addr_reduce_fn, (void *) &sp);

	return(0);
}

int
info_get_services_alumni(char *name, cf_dyn_buf *db)
{
	services_printer sp;
	sp.printed_element = false;
	sp.db = db;

	shash_reduce(g_info_node_info_history_hash, info_get_services_reduce_fn, (void *) &sp);

	return(0);
}

//
// This dynamic function removes nodes from g_info_node_info_history_hash that
// aren't present in g_info_node_info_hash.
//
int
history_purge_reduce_fn(void *key, void *data, void *udata)
{
	return SHASH_OK == shash_get(g_info_node_info_hash, key, NULL) ? SHASH_OK : SHASH_REDUCE_DELETE;
}

int
info_services_alumni_reset(char *name, cf_dyn_buf *db)
{
	shash_reduce_delete(g_info_node_info_history_hash, history_purge_reduce_fn, NULL);
	cf_info(AS_INFO, "services alumni list reset");
	cf_dyn_buf_append_string(db, "ok");

	return(0);
}



//
// Iterate through the current namespace list and cons up a string
//

int
info_get_namespaces(char *name, cf_dyn_buf *db)
{
	for (uint i = 0; i < g_config.n_namespaces; i++) {
		cf_dyn_buf_append_string(db, g_config.namespaces[i]->name);
		cf_dyn_buf_append_char(db, ';');
	}

	if (g_config.n_namespaces > 0) {
		cf_dyn_buf_chomp(db);
	}

	return(0);
}

int
info_get_logs(char *name, cf_dyn_buf *db)
{
	cf_fault_sink_strlist(db);
	return(0);
}

int
info_get_objects(char *name, cf_dyn_buf *db)
{
	uint64_t	objects = 0;

	for (uint i = 0; i < g_config.n_namespaces; i++) {
		objects += g_config.namespaces[i]->n_objects;
	}

	cf_dyn_buf_append_uint64(db, objects);
	return(0);
}

int
info_get_sets(char *name, cf_dyn_buf *db)
{
	return info_get_tree_sets(name, "", db);
}

int
info_get_bins(char *name, cf_dyn_buf *db)
{
	return info_get_tree_bins(name, "", db);
}

int
info_get_config( char* name, cf_dyn_buf *db)
{
	return info_command_config_get(name, NULL, db);
}

int
info_get_sindexes(char *name, cf_dyn_buf *db)
{
	return info_get_tree_sindexes(name, "", db);
}


void
info_get_namespace_info(as_namespace *ns, cf_dyn_buf *db)
{
	// Object counts.

	info_append_uint64(db, "objects", ns->n_objects);
	info_append_uint64(db, "sub_objects", ns->n_sub_objects);

	as_master_prole_stats mp;
	as_partition_get_master_prole_stats(ns, &mp);

	info_append_uint64(db, "master_objects", mp.n_master_records);
	info_append_uint64(db, "master_sub_objects", mp.n_master_sub_records);
	info_append_uint64(db, "prole_objects", mp.n_prole_records);
	info_append_uint64(db, "prole_sub_objects", mp.n_prole_sub_records);

	// Expiration & eviction (nsup) stats.

	info_append_bool(db, "stop_writes", ns->stop_writes != 0);
	info_append_bool(db, "hwm_breached", ns->hwm_breached != 0);

	info_append_uint64(db, "current_time", as_record_void_time_get());
	info_append_uint64(db, "max_void_time", ns->max_void_time);
	info_append_uint64(db, "non_expirable_objects", ns->non_expirable_objects);
	info_append_uint64(db, "expired_objects", ns->n_expired_objects);
	info_append_uint64(db, "evicted_objects", ns->n_evicted_objects);
	info_append_uint64(db, "set_deleted_objects", ns->n_deleted_set_objects);
	info_append_uint64(db, "evict_ttl", ns->evict_ttl);
	info_append_uint32(db, "nsup_cycle_duration", ns->nsup_cycle_duration);
	info_append_uint32(db, "nsup_cycle_sleep_pct", ns->nsup_cycle_sleep_pct);

	// Memory usage stats.

	uint64_t data_memory = ns->n_bytes_memory;
	uint64_t index_memory = as_index_size_get(ns) * (ns->n_objects + ns->n_sub_objects);
	uint64_t sindex_memory = ns->sindex_data_memory_used;
	uint64_t used_memory = data_memory + index_memory + sindex_memory;

	info_append_uint64(db, "memory_used_bytes", used_memory);
	info_append_uint64(db, "memory_used_data_bytes", data_memory);
	info_append_uint64(db, "memory_used_index_bytes", index_memory);
	info_append_uint64(db, "memory_used_sindex_bytes", sindex_memory);

	uint64_t free_pct = (ns->memory_size != 0 && (ns->memory_size > used_memory)) ?
			((ns->memory_size - used_memory) * 100L) / ns->memory_size : 0;

	info_append_uint64(db, "memory_free_pct", free_pct);

	// Remaining bin-name slots (yes, this can be negative).
	if (! ns->single_bin) {
		info_append_int(db, "available_bin_names", BIN_NAMES_QUOTA - (int)cf_vmapx_count(ns->p_bin_name_vmap));
	}

	// Persistent storage stats.

	if (ns->storage_type == AS_STORAGE_ENGINE_SSD) {
		int available_pct = 0;
		uint64_t inuse_disk_bytes = 0;
		as_storage_stats(ns, &available_pct, &inuse_disk_bytes);

		info_append_uint64(db, "device_total_bytes", ns->ssd_size);
		info_append_uint64(db, "device_used_bytes", inuse_disk_bytes);

		free_pct = (ns->ssd_size != 0 && (ns->ssd_size > inuse_disk_bytes)) ?
				((ns->ssd_size - inuse_disk_bytes) * 100L) / ns->ssd_size : 0;

		info_append_uint64(db, "device_free_pct", free_pct);
		info_append_int(db, "device_available_pct", available_pct);

		if (! ns->storage_data_in_memory) {
			info_append_int(db, "cache_read_pct", (int)(ns->cache_read_pct + 0.5));
		}
	}

	// Not bothering with AS_STORAGE_ENGINE_KV.

	// Migration stats.

	info_append_uint64(db, "migrate_tx_partitions_imbalance", ns->migrate_tx_partitions_imbalance);

	info_append_uint64(db, "migrate_tx_instances", ns->migrate_tx_instance_count);
	info_append_uint64(db, "migrate_rx_instances", ns->migrate_rx_instance_count);

	info_append_uint64(db, "migrate_tx_partitions_active", ns->migrate_tx_partitions_active);
	info_append_uint64(db, "migrate_rx_partitions_active", ns->migrate_rx_partitions_active);

	info_append_uint64(db, "migrate_tx_partitions_initial", ns->migrate_tx_partitions_initial);
	info_append_uint64(db, "migrate_tx_partitions_remaining", ns->migrate_tx_partitions_remaining);

	info_append_uint64(db, "migrate_rx_partitions_initial", ns->migrate_rx_partitions_initial);
	info_append_uint64(db, "migrate_rx_partitions_remaining", ns->migrate_rx_partitions_remaining);

	info_append_uint64(db, "migrate_records_skipped", ns->migrate_records_skipped);
	info_append_uint64(db, "migrate_records_transmitted", ns->migrate_records_transmitted);
	info_append_uint64(db, "migrate_record_retransmits", ns->migrate_record_retransmits);
	info_append_uint64(db, "migrate_record_receives", ns->migrate_record_receives);

	// From-client transaction stats.

	info_append_uint64(db, "client_tsvc_error", ns->n_client_tsvc_error);
	info_append_uint64(db, "client_tsvc_timeout", ns->n_client_tsvc_timeout);

	info_append_uint64(db, "client_proxy_complete", ns->n_client_proxy_complete);
	info_append_uint64(db, "client_proxy_error", ns->n_client_proxy_error);
	info_append_uint64(db, "client_proxy_timeout", ns->n_client_proxy_timeout);

	info_append_uint64(db, "client_read_success", ns->n_client_read_success);
	info_append_uint64(db, "client_read_error", ns->n_client_read_error);
	info_append_uint64(db, "client_read_timeout", ns->n_client_read_timeout);
	info_append_uint64(db, "client_read_not_found", ns->n_client_read_not_found);

	info_append_uint64(db, "client_write_success", ns->n_client_write_success);
	info_append_uint64(db, "client_write_error", ns->n_client_write_error);
	info_append_uint64(db, "client_write_timeout", ns->n_client_write_timeout);

	// Subset of n_client_write_... above, respectively.
	info_append_uint64(db, "xdr_write_success", ns->n_xdr_write_success);
	info_append_uint64(db, "xdr_write_error", ns->n_xdr_write_error);
	info_append_uint64(db, "xdr_write_timeout", ns->n_xdr_write_timeout);

	info_append_uint64(db, "client_delete_success", ns->n_client_delete_success);
	info_append_uint64(db, "client_delete_error", ns->n_client_delete_error);
	info_append_uint64(db, "client_delete_timeout", ns->n_client_delete_timeout);
	info_append_uint64(db, "client_delete_not_found", ns->n_client_delete_not_found);

	info_append_uint64(db, "client_udf_complete", ns->n_client_udf_complete);
	info_append_uint64(db, "client_udf_error", ns->n_client_udf_error);
	info_append_uint64(db, "client_udf_timeout", ns->n_client_udf_timeout);

	info_append_uint64(db, "client_lang_read_success", ns->n_client_lang_read_success);
	info_append_uint64(db, "client_lang_write_success", ns->n_client_lang_write_success);
	info_append_uint64(db, "client_lang_delete_success", ns->n_client_lang_delete_success);
	info_append_uint64(db, "client_lang_error", ns->n_client_lang_error);

	// Batch sub-transaction stats.

	info_append_uint64(db, "batch_sub_tsvc_error", ns->n_batch_sub_tsvc_error);
	info_append_uint64(db, "batch_sub_tsvc_timeout", ns->n_batch_sub_tsvc_timeout);

	info_append_uint64(db, "batch_sub_proxy_complete", ns->n_batch_sub_proxy_complete);
	info_append_uint64(db, "batch_sub_proxy_error", ns->n_batch_sub_proxy_error);
	info_append_uint64(db, "batch_sub_proxy_timeout", ns->n_batch_sub_proxy_timeout);

	info_append_uint64(db, "batch_sub_read_success", ns->n_batch_sub_read_success);
	info_append_uint64(db, "batch_sub_read_error", ns->n_batch_sub_read_error);
	info_append_uint64(db, "batch_sub_read_timeout", ns->n_batch_sub_read_timeout);
	info_append_uint64(db, "batch_sub_read_not_found", ns->n_batch_sub_read_not_found);

	// Internal-UDF sub-transaction stats.

	info_append_uint64(db, "udf_sub_tsvc_error", ns->n_udf_sub_tsvc_error);
	info_append_uint64(db, "udf_sub_tsvc_timeout", ns->n_udf_sub_tsvc_timeout);

	info_append_uint64(db, "udf_sub_udf_complete", ns->n_udf_sub_udf_complete);
	info_append_uint64(db, "udf_sub_udf_error", ns->n_udf_sub_udf_error);
	info_append_uint64(db, "udf_sub_udf_timeout", ns->n_udf_sub_udf_timeout);

	info_append_uint64(db, "udf_sub_lang_read_success", ns->n_udf_sub_lang_read_success);
	info_append_uint64(db, "udf_sub_lang_write_success", ns->n_udf_sub_lang_write_success);
	info_append_uint64(db, "udf_sub_lang_delete_success", ns->n_udf_sub_lang_delete_success);
	info_append_uint64(db, "udf_sub_lang_error", ns->n_udf_sub_lang_error);

	// Scan stats.

	info_append_uint64(db, "scan_basic_complete", ns->n_scan_basic_complete);
	info_append_uint64(db, "scan_basic_error", ns->n_scan_basic_error);
	info_append_uint64(db, "scan_basic_abort", ns->n_scan_basic_abort);

	info_append_uint64(db, "scan_aggr_complete", ns->n_scan_aggr_complete);
	info_append_uint64(db, "scan_aggr_error", ns->n_scan_aggr_error);
	info_append_uint64(db, "scan_aggr_abort", ns->n_scan_aggr_abort);

	info_append_uint64(db, "scan_udf_bg_complete", ns->n_scan_udf_bg_complete);
	info_append_uint64(db, "scan_udf_bg_error", ns->n_scan_udf_bg_error);
	info_append_uint64(db, "scan_udf_bg_abort", ns->n_scan_udf_bg_abort);

	// Query stats.

	uint64_t agg			= ns->n_aggregation;
	uint64_t agg_success	= ns->n_agg_success;
	uint64_t agg_err		= ns->n_agg_errs;
	uint64_t agg_abort		= ns->n_agg_abort;
	uint64_t agg_records	= ns->agg_num_records;

	uint64_t lkup			= ns->n_lookup;
	uint64_t lkup_success	= ns->n_lookup_success;
	uint64_t lkup_err		= ns->n_lookup_errs;
	uint64_t lkup_abort		= ns->n_lookup_abort;
	uint64_t lkup_records	= ns->lookup_num_records;

	info_append_uint64(db, "query_reqs", ns->query_reqs);
	info_append_uint64(db, "query_fail", ns->query_fail);

	info_append_uint64(db, "query_short_queue_full", ns->query_short_queue_full);
	info_append_uint64(db, "query_long_queue_full", ns->query_long_queue_full);
	info_append_uint64(db, "query_short_reqs", ns->query_short_reqs);
	info_append_uint64(db, "query_long_reqs", ns->query_long_reqs);

	info_append_uint64(db, "query_agg", agg);
	info_append_uint64(db, "query_agg_success", agg_success);
	info_append_uint64(db, "query_agg_error", agg_err);
	info_append_uint64(db, "query_agg_abort", agg_abort);
	info_append_uint64(db, "query_agg_avg_rec_count", agg ? agg_records / agg : 0);

	info_append_uint64(db, "query_lookups", lkup);
	info_append_uint64(db, "query_lookup_success", lkup_success);
	info_append_uint64(db, "query_lookup_error", lkup_err);
	info_append_uint64(db, "query_lookup_abort", lkup_abort);
	info_append_uint64(db, "query_lookup_avg_rec_count", lkup ? lkup_records / lkup : 0);

	info_append_uint64(db, "query_udf_bg_success", ns->n_query_udf_bg_success);
	info_append_uint64(db, "query_udf_bg_failure", ns->n_query_udf_bg_failure);

	// Geospatial query stats:
	info_append_uint64(db, "geo_region_query_reqs", ns->geo_region_query_count);
	info_append_uint64(db, "geo_region_query_cells", ns->geo_region_query_cells);
	info_append_uint64(db, "geo_region_query_points", ns->geo_region_query_points);
	info_append_uint64(db, "geo_region_query_falsepos", ns->geo_region_query_falsepos);

	// Special errors that deserve their own counters:

	info_append_uint64(db, "fail_xdr_forbidden", ns->n_fail_xdr_forbidden);
	info_append_uint64(db, "fail_key_busy", ns->n_fail_key_busy);
	info_append_uint64(db, "fail_generation", ns->n_fail_generation);
	info_append_uint64(db, "fail_record_too_big", ns->n_fail_record_too_big);

	// Special non-error counters:

	info_append_uint64(db, "deleted_last_bin", ns->n_deleted_last_bin);

	// LDT stats.

	if (ns->ldt_enabled) {
		info_append_uint64(db, "ldt_reads", ns->lstats.ldt_read_reqs);
		info_append_uint64(db, "ldt_read_success", ns->lstats.ldt_read_success);
		info_append_uint64(db, "ldt_deletes", ns->lstats.ldt_delete_reqs);
		info_append_uint64(db, "ldt_delete_success", ns->lstats.ldt_delete_success);
		info_append_uint64(db, "ldt_writes", ns->lstats.ldt_write_reqs);
		info_append_uint64(db, "ldt_write_success", ns->lstats.ldt_write_success);
		info_append_uint64(db, "ldt_updates", ns->lstats.ldt_update_reqs);

		info_append_uint64(db, "ldt_gc_io", ns->lstats.ldt_gc_io);
		info_append_uint64(db, "ldt_gc_cnt", ns->lstats.ldt_gc_cnt);
		info_append_uint64(db, "ldt_randomizer_retry", ns->lstats.ldt_randomizer_retry);

		info_append_uint64(db, "ldt_errors", ns->lstats.ldt_errs);

		info_append_uint64(db, "ldt_err_toprec_notfound", ns->lstats.ldt_err_toprec_not_found);
		info_append_uint64(db, "ldt_err_item_notfound", ns->lstats.ldt_err_item_not_found);
		info_append_uint64(db, "ldt_err_internal", ns->lstats.ldt_err_internal);
		info_append_uint64(db, "ldt_err_unique_key_violation", ns->lstats.ldt_err_unique_key_violation);
		info_append_uint64(db, "ldt_err_insert_fail", ns->lstats.ldt_err_insert_fail);
		info_append_uint64(db, "ldt_err_delete_fail", ns->lstats.ldt_err_delete_fail);
		info_append_uint64(db, "ldt_err_search_fail", ns->lstats.ldt_err_search_fail);
		info_append_uint64(db, "ldt_err_version_mismatch", ns->lstats.ldt_err_version_mismatch);
		info_append_uint64(db, "ldt_err_capacity_exceeded", ns->lstats.ldt_err_capacity_exceeded);
		info_append_uint64(db, "ldt_err_param", ns->lstats.ldt_err_param);
		info_append_uint64(db, "ldt_err_op_bintype_mismatch", ns->lstats.ldt_err_op_bintype_mismatch);
		info_append_uint64(db, "ldt_err_too_many_open_subrec", ns->lstats.ldt_err_too_many_open_subrec);
		info_append_uint64(db, "ldt_err_subrec_not_found", ns->lstats.ldt_err_subrec_not_found);
		info_append_uint64(db, "ldt_err_bin_does_not_exist", ns->lstats.ldt_err_bin_does_not_exist);
		info_append_uint64(db, "ldt_err_bin_exits", ns->lstats.ldt_err_bin_exits);
		info_append_uint64(db, "ldt_err_bin_damaged", ns->lstats.ldt_err_bin_damaged);
		info_append_uint64(db, "ldt_err_toprec_internal", ns->lstats.ldt_err_toprec_internal);
		info_append_uint64(db, "ldt_err_subrec_internal", ns->lstats.ldt_err_subrec_internal);
		info_append_uint64(db, "ldt_err_filer", ns->lstats.ldt_err_filter);
		info_append_uint64(db, "ldt_err_key", ns->lstats.ldt_err_key);
		info_append_uint64(db, "ldt_err_createspec", ns->lstats.ldt_err_createspec);
		info_append_uint64(db, "ldt_err_usermodule", ns->lstats.ldt_err_usermodule);
		info_append_uint64(db, "ldt_err_input_too_large", ns->lstats.ldt_err_input_too_large);
		info_append_uint64(db, "ldt_err_ldt_not_enabled", ns->lstats.ldt_err_ldt_not_enabled);
		info_append_uint64(db, "ldt_err_unknown", ns->lstats.ldt_err_unknown);
	}
}

//
// Iterate through the current namespace list and cons up a string
//

int
info_get_tree_namespace(char *name, char *subtree, cf_dyn_buf *db)
{
	as_namespace *ns = as_namespace_get_byname(subtree);

	if (! ns)   {
		cf_dyn_buf_append_string(db, "type=unknown"); // TODO - better message?
		return 0;
	}

	info_get_namespace_info(ns, db);
	info_namespace_config_get(ns->name, db);

	cf_dyn_buf_chomp(db);

	return 0;
}

int
info_get_tree_sets(char *name, char *subtree, cf_dyn_buf *db)
{
	char *set_name    = NULL;
	as_namespace *ns  = NULL;

	// if there is a subtree, get the namespace
	if (subtree && strlen(subtree) > 0) {
		// see if subtree has a sep as well
		set_name = strchr(subtree, TREE_SEP);

		// pull out namespace, and namespace name...
		if (set_name) {
			int ns_name_len = (set_name - subtree);
			char ns_name[ns_name_len + 1];
			memcpy(ns_name, subtree, ns_name_len);
			ns_name[ns_name_len] = '\0';
			ns = as_namespace_get_byname(ns_name);
			set_name++; // currently points to the TREE_SEP, which is not what we want.
		}
		else {
			ns = as_namespace_get_byname(subtree);
		}

		if (!ns) {
			cf_dyn_buf_append_string(db, "ns_type=unknown");
			return(0);
		}
	}

	// format w/o namespace is ns1:set1:prop1=val1:prop2=val2:..propn=valn;ns1:set2...;ns2:set1...;
	if (!ns) {
		for (uint i = 0; i < g_config.n_namespaces; i++) {
			as_namespace_get_set_info(g_config.namespaces[i], set_name, db);
		}
	}
	// format w namespace w/o set name is ns:set1:prop1=val1:prop2=val2...propn=valn;ns:set2...;
	// format w namespace & set name is prop1=val1:prop2=val2...propn=valn;
	else {
		as_namespace_get_set_info(ns, set_name, db);
	}
	return(0);
}

int
info_get_tree_bins(char *name, char *subtree, cf_dyn_buf *db)
{
	as_namespace *ns  = NULL;

	// if there is a subtree, get the namespace
	if (subtree && strlen(subtree) > 0) {
		ns = as_namespace_get_byname(subtree);

		if (!ns) {
			cf_dyn_buf_append_string(db, "ns_type=unknown");
			return 0;
		}
	}

	// format w/o namespace is
	// ns:num-bin-names=val1,bin-names-quota=val2,name1,name2,...;ns:...
	if (!ns) {
		for (uint i = 0; i < g_config.n_namespaces; i++) {
			as_namespace_get_bins_info(g_config.namespaces[i], db, true);
		}
	}
	// format w/namespace is
	// num-bin-names=val1,bin-names-quota=val2,name1,name2,...
	else {
		as_namespace_get_bins_info(ns, db, false);
	}

	return 0;
}

int
info_command_hist_dump(char *name, char *params, cf_dyn_buf *db)
{
	char value_str[128];
	int  value_str_len = sizeof(value_str);

	if (0 != as_info_parameter_get(params, "ns", value_str, &value_str_len)) {
		cf_info(AS_INFO, "hist-dump %s command: no namespace specified", name);
		cf_dyn_buf_append_string(db, "error-no-namespace");
		return 0;
	}

	as_namespace *ns = as_namespace_get_byname(value_str);

	if (!ns) {
		cf_info(AS_INFO, "hist-dump %s command: unknown namespace: %s", name, value_str);
		cf_dyn_buf_append_string(db, "error-unknown-namespace");
		return 0;
	}

	value_str_len = sizeof(value_str);

	if (0 != as_info_parameter_get(params, "hist", value_str, &value_str_len)) {
		cf_info(AS_INFO, "hist-dump %s command:", name);
		cf_dyn_buf_append_string(db, "error-no-hist-name");

		return 0;
	}

	// get optional set field
	char set_name_str[AS_SET_NAME_MAX_SIZE];
	int set_name_str_len = sizeof(set_name_str);
	set_name_str[0] = 0;

	as_info_parameter_get(params, "set", set_name_str, &set_name_str_len);

	// format is ns1:ns_hist1=bucket_count,offset,b1,b2,b3...;
	as_namespace_get_hist_info(ns, set_name_str, value_str, db, true);

	return 0;
}


int
info_get_tree_log(char *name, char *subtree, cf_dyn_buf *db)
{
	// see if subtree has a sep as well
	int sink_id;
	char *context = strchr(subtree, TREE_SEP);
	if (context) { // this means: log/id/context ,
		*context = 0;
		context++;

		if (0 != cf_str_atoi(subtree, &sink_id)) return(-1);

		cf_fault_sink_context_strlist(sink_id, context, db);
	}
	else { // this means just: log/id , so get all contexts
		if (0 != cf_str_atoi(subtree, &sink_id)) return(-1);

		cf_fault_sink_context_all_strlist(sink_id, db);
	}

	return(0);
}


int
info_get_tree_sindexes(char *name, char *subtree, cf_dyn_buf *db)
{
	char *index_name    = NULL;
	as_namespace *ns  = NULL;

	// if there is a subtree, get the namespace
	if (subtree && strlen(subtree) > 0) {
		// see if subtree has a sep as well
		index_name = strchr(subtree, TREE_SEP);

		// pull out namespace, and namespace name...
		if (index_name) {
			int ns_name_len = (index_name - subtree);
			char ns_name[ns_name_len + 1];
			memcpy(ns_name, subtree, ns_name_len);
			ns_name[ns_name_len] = '\0';
			ns = as_namespace_get_byname(ns_name);
			index_name++; // currently points to the TREE_SEP, which is not what we want.
		}
		else {
			ns = as_namespace_get_byname(subtree);
		}

		if (!ns) {
			cf_dyn_buf_append_string(db, "ns_type=unknown");
			return(0);
		}
	}

	// format w/o namespace is:
	//    ns=ns1:set=set1:indexname=index1:prop1=val1:...:propn=valn;ns=ns1:set=set2:indexname=index2:...;ns=ns2:set=set1:...;
	if (!ns) {
		for (uint i = 0; i < g_config.n_namespaces; i++) {
			as_sindex_list_str(g_config.namespaces[i], db);
		}
	}
	// format w namespace w/o index name is:
	//    ns=ns1:set=set1:indexname=index1:prop1=val1:...:propn=valn;ns=ns1:set=set2:indexname=indexname2:...;
	else if (!index_name) {
		as_sindex_list_str(ns, db);
	}
	else {
		// format w namespace & index name is:
		//    prop1=val1;prop2=val2;...;propn=valn
		int resp = as_sindex_stats_str(ns, index_name, db);
		if (resp) {
			cf_warning(AS_INFO, "Failed to get statistics for index %s: err = %d", index_name, resp);
			INFO_COMMAND_SINDEX_FAILCODE(
					as_sindex_err_to_clienterr(resp, __FILE__, __LINE__),
					as_sindex_err_str(resp));
		}
	}
	return(0);
}

int
info_get_service(char *name, cf_dyn_buf *db)
{
	pthread_mutex_lock(&g_service_lock);
	cf_dyn_buf_append_string(db, g_service_str ? g_service_str : " ");
	pthread_mutex_unlock(&g_service_lock);

	return(0);
}

void
clear_ldt_histograms()
{
	histogram_clear(g_stats.ldt_multiop_prole_hist);
	histogram_clear(g_stats.ldt_update_record_cnt_hist);
	histogram_clear(g_stats.ldt_io_record_cnt_hist);
	histogram_clear(g_stats.ldt_update_io_bytes_hist);
	histogram_clear(g_stats.ldt_hist);
}

// SINDEX wire protocol examples:
// 1.) NUMERIC:    sindex-create:ns=usermap;set=demo;indexname=um_age;indexdata=age,numeric
// 2.) STRING:     sindex-create:ns=usermap;set=demo;indexname=um_state;indexdata=state,string
/*
 *  Parameters:
 *  	params --- string passed to asinfo call
 *  	imd    --  parses the params and fills this sindex struct.
 *
 *  Returns
 *  	AS_SINDEX_OK if it successfully fills up imd
 *      AS_SINDEX_ERR_PARAM otherwise
 *     TODO REVIEW  : send cmd as argument
 */
int
as_info_parse_params_to_sindex_imd(char* params, as_sindex_metadata *imd, cf_dyn_buf* db,
		bool is_create, bool *is_smd_op, char * cmd)
{
	if (!imd) {
		cf_warning(AS_INFO, "%s : Failed. internal error", cmd);
		return AS_SINDEX_ERR_PARAM;
	}
	imd->post_op     = 0;

	char indexname_str[AS_ID_INAME_SZ];
	int  indname_len  = sizeof(indexname_str);
	int ret = as_info_parameter_get(params, STR_INDEXNAME, indexname_str, &indname_len);
	if ( ret == -1 ) {
		cf_warning(AS_INFO, "%s : Failed. Indexname not specified", cmd);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Index Name Not Specified");
		return AS_SINDEX_ERR_PARAM;
	}
	else if ( ret == -2 ) {
		cf_warning(AS_INFO, "%s : Failed. The indexname is longer than %d characters", cmd,
				AS_ID_INAME_SZ-1);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Indexname too long");
		return AS_SINDEX_ERR_PARAM;
	}

	char ns_str[AS_ID_NAMESPACE_SZ];
	int ns_len       = sizeof(ns_str);
	ret = as_info_parameter_get(params, STR_NS, ns_str, &ns_len);
	if ( ret == -1 ) {
		cf_warning(AS_INFO, "%s : Failed. Namespace not specified for index %s ", cmd, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Namespace Not Specified");
		return AS_SINDEX_ERR_PARAM;
	}
	else if (ret == -2 ) {
		cf_warning(AS_INFO, "%s : Failed. Name of the namespace is longer than %d characters"
			" for index %s ", cmd, AS_ID_NAMESPACE_SZ-1, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Name of the namespace is too long");
		return AS_SINDEX_ERR_PARAM;
	}
	as_namespace *ns = as_namespace_get_byname(ns_str);
	if (!ns) {
		cf_warning(AS_INFO, "%s : Failed. namespace %s not found for index %s", cmd, ns_str,
					indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Namespace Not Found");
		return AS_SINDEX_ERR_PARAM;
	}
	if (ns->single_bin) {
		cf_warning(AS_INFO, "%s : Failed. Secondary Index is not allowed on single bin "
				"namespace %s for index %s", cmd, ns_str, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Single bin namespace");
		return AS_SINDEX_ERR_PARAM;
	}

	char set_str[AS_SET_NAME_MAX_SIZE];
	int set_len  = sizeof(set_str);
	if (imd->set) {
		cf_free(imd->set);
		imd->set = NULL;
	}
	ret = as_info_parameter_get(params, STR_SET, set_str, &set_len);
	if (!ret) {
		imd->set = cf_strdup(set_str);
	} else if (ret == -2) {
		cf_warning(AS_INFO, "%s : Failed. Setname is longer than %d for index %s",
				cmd, AS_SET_NAME_MAX_SIZE-1, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Name of the set is too long");
		return AS_SINDEX_ERR_PARAM;
	}

	char cluster_op[6];
	int cluster_op_len = sizeof(cluster_op);
	if (as_info_parameter_get(params, "cluster_op", cluster_op, &cluster_op_len) != 0) {
		*is_smd_op = true;
	}
	else if (strcmp(cluster_op, "true") == 0) {
		*is_smd_op = true;
	}
	else if (strcmp(cluster_op, "false") == 0) {
		*is_smd_op = false;
	}

	// Delete only need parsing till here
	if (!is_create) {
		imd->ns_name = cf_strdup(ns->name);
		imd->iname   = cf_strdup(indexname_str);
		return 0;
	}

	char indextype_str[AS_SINDEX_TYPE_STR_SIZE];
	int  indtype_len = sizeof(indextype_str);
	ret = as_info_parameter_get(params, STR_ITYPE, indextype_str, &indtype_len);
	if (ret == -1) {
		// if not specified the index type is DEFAULT
		imd->itype = AS_SINDEX_ITYPE_DEFAULT;
	}
	else if (ret == -2) {
		cf_warning(AS_INFO, "%s : Failed. Indextype str  is longer than %d for index %s",
				cmd, AS_SINDEX_TYPE_STR_SIZE-1, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Indextype str is too long");
		return AS_SINDEX_ERR_PARAM;

	}
	else {
		if (strncasecmp(indextype_str, STR_ITYPE_DEFAULT, 7) == 0) {
			imd->itype = AS_SINDEX_ITYPE_DEFAULT;
		}
		else if (strncasecmp(indextype_str, STR_ITYPE_LIST, 4) == 0) {
			imd->itype = AS_SINDEX_ITYPE_LIST;
		}
		else if (strncasecmp(indextype_str, STR_ITYPE_MAPKEYS, 7) == 0) {
			imd->itype = AS_SINDEX_ITYPE_MAPKEYS;
		}
		else if (strncasecmp(indextype_str, STR_ITYPE_MAPVALUES, 9) == 0) {
			imd->itype = AS_SINDEX_ITYPE_MAPVALUES;
		}
		else {
			cf_warning(AS_INFO, "%s : Failed. Invalid indextype %s for index %s",
					cmd, indextype_str, indexname_str);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
					"Invalid type. Should be one of [DEFAULT, LIST, MAPKEYS, MAPVALUES]");
			return AS_SINDEX_ERR_PARAM;
		}
	}

	// Indexdata = binpath,keytype
	char indexdata_str[AS_SINDEXDATA_STR_SIZE];
	int  indexdata_len = sizeof(indexdata_str);
	if (as_info_parameter_get(params, STR_INDEXDATA, indexdata_str, &indexdata_len)) {
		cf_warning(AS_INFO, "%s : Failed. Invalid indexdata %s for index %s",
				cmd, indexdata_str, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Invalid indexdata");
		return AS_SINDEX_ERR_PARAM;
	}
	cf_vector *str_v = cf_vector_create(sizeof(void *), 10, VECTOR_FLAG_INITZERO);
	cf_str_split(",", indexdata_str, str_v);
	if (2 != (cf_vector_size(str_v))) {
		cf_warning(AS_INFO, "%s : Failed. Number of bins more than 1 for index %s",
				cmd, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Number of bins more than 1");
		cf_vector_destroy(str_v);
		return AS_SINDEX_ERR_PARAM;
	}

	char * path_str;
	cf_vector_get(str_v, 0, &path_str);
	if (as_sindex_extract_bin_path(imd, path_str)) {
		cf_warning(AS_INFO, "%s : Failed. Path_str is not valid- %s", cmd, path_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Invalid path");
		return AS_SINDEX_ERR_PARAM;
	}
	if (!imd->bname) {
		cf_warning(AS_INFO, "%s : Failed. Invalid bin name", cmd);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Invalid bin name");
		cf_vector_destroy(str_v);
		return AS_SINDEX_ERR_PARAM;
	}
	char *type_str = NULL;
	cf_vector_get(str_v, 1, &type_str);
	if (!type_str) {
		cf_warning(AS_INFO, "%s : Failed. Bin type is null for index %s ", cmd, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Invalid type. Should be one"
				" of [numeric,string,geo2dsphere]");
		cf_vector_destroy(str_v);
		return AS_SINDEX_ERR_PARAM;
	}

	as_sindex_ktype ktype = as_sindex_ktype_from_string(type_str);
	if (ktype == AS_SINDEX_KTYPE_NONE) {
		cf_warning(AS_INFO, "%s : Failed. Invalid bin type %s for index %s", cmd,
				type_str, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Invalid type. Should be one of [numeric,string,geo2dsphere]");
		cf_vector_destroy(str_v);
		return AS_SINDEX_ERR_PARAM;
	}
	imd->btype = ktype;

	if (imd->bname && strlen(imd->bname) >= AS_ID_BIN_SZ) {
		cf_warning(AS_INFO, "%s : Failed. Bin Name %s longer than allowed %d for index %s",
				cmd, imd->bname, AS_ID_BIN_SZ-1, indexname_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Bin Name too long");
		cf_vector_destroy(str_v);
		return AS_SINDEX_ERR_PARAM;
	}

	cf_vector_destroy(str_v);

	if (is_create) {
		imd->ns_name = cf_strdup(ns->name);
		imd->iname   = cf_strdup(indexname_str);
	}
	imd->path_str = cf_strdup(path_str);
	return AS_SINDEX_OK;
}

int info_command_sindex_create(char *name, char *params, cf_dyn_buf *db)
{
	as_sindex_metadata imd;
	memset((void *)&imd, 0, sizeof(imd));
	bool is_smd_op = true;

	// Check info-command params for correctness.
	int res = as_info_parse_params_to_sindex_imd(params, &imd, db, true, &is_smd_op, "SINDEX CREATE");

	if (res != 0) {
		goto ERR;
	}

	as_namespace *ns = as_namespace_get_byname(imd.ns_name);
	res = as_sindex_create_check_params(ns, &imd);

	if (res == AS_SINDEX_ERR_FOUND) {
		cf_warning(AS_INFO, "SINDEX CREATE : Index with the same index defn already exists or bin has "
				"already been indexed.");
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_INDEX_FOUND,
				"Index with the same name already exists or this bin has already been indexed.");
		goto ERR;
	}
	else if (res == AS_SINDEX_ERR_MAXCOUNT) {
		cf_warning(AS_INFO, "SINDEX CREATE : More than %d index are not allowed per namespace.", AS_SINDEX_MAX);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_INDEX_MAXCOUNT,
				"Reached maximum number of sindex allowed");
		goto ERR;
	}

	if (is_smd_op == true)
	{
		cf_info(AS_INFO, "SINDEX CREATE : Request received for %s:%s via SMD", imd.ns_name, imd.iname);
		char module[] = SINDEX_MODULE;
		char key[SINDEX_SMD_KEY_SIZE];
		sprintf(key, "%s:%s", imd.ns_name, imd.iname);
		// TODO : Send imd instead of params as value.
		// Today as_info_parse_params_to_sindex_imd is done again by smd layer
		res = as_smd_set_metadata(module, key, params);

		if (res != 0) {
			cf_warning(AS_INFO, "SINDEX CREATE : Queuing the index %s metadata to SMD failed with error %s",
					imd.iname, as_sindex_err_str(res));
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, as_sindex_err_str(res));
			goto ERR;
		}
	}
	else if (is_smd_op == false) {
		cf_info(AS_INFO, "SINDEX CREATE : Request received for %s:%s via info", imd.ns_name, imd.iname);
		res = as_sindex_create(ns, &imd, true);
		if (0 != res) {
			cf_warning(AS_INFO, "SINDEX CREATE : Failed with error %s for index %s",
					as_sindex_err_str(res), imd.iname);
			INFO_COMMAND_SINDEX_FAILCODE(as_sindex_err_to_clienterr(res, __FILE__, __LINE__),
					as_sindex_err_str(res));
			goto ERR;
		}
	}
	cf_dyn_buf_append_string(db, "OK");
ERR:
	as_sindex_imd_free(&imd);
	return(0);

}

int info_command_sindex_delete(char *name, char *params, cf_dyn_buf *db) {
	as_sindex_metadata imd;
	memset((void *)&imd, 0, sizeof(imd));
	bool is_smd_op = true;
	int res = as_info_parse_params_to_sindex_imd(params, &imd, db, false, &is_smd_op, "SINDEX DROP");

	if (res != 0) {
		goto ERR;
	}

	as_namespace *ns = as_namespace_get_byname(imd.ns_name);

	// Do not use as_sindex_exists_by_defn() here, it'll fail because bname is null.
	if (!as_sindex_delete_checker(ns, &imd)) {
		cf_warning(AS_INFO, "SINDEX DROP : Index %s:%s does not exist on the system",
				imd.ns_name, imd.iname);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_INDEX_NOTFOUND,
				"Index does not exist on the system.");
		goto ERR;
	}

	if (is_smd_op == true)
	{
		cf_info(AS_INFO, "SINDEX DROP : Request received for %s:%s via SMD", imd.ns_name, imd.iname);
		char module[] = SINDEX_MODULE;
		char key[SINDEX_SMD_KEY_SIZE];
		sprintf(key, "%s:%s", imd.ns_name, imd.iname);
		res = as_smd_delete_metadata(module, key);
		if (0 != res) {
			cf_warning(AS_INFO, "SINDEX DROP : Queuing the index %s metadata to SMD failed with error %s",
					imd.iname, as_sindex_err_str(res));
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, as_sindex_err_str(res));
			goto ERR;
		}
	}
	else if(is_smd_op == false)
	{
		cf_info(AS_INFO, "SINDEX DROP : Request received for %s:%s via info", imd.ns_name, imd.iname);
		res = as_sindex_destroy(ns, &imd);
		if (0 != res) {
			cf_warning(AS_INFO, "SINDEX DROP : Failed with error %s for index %s",
					as_sindex_err_str(res), imd.iname);
			INFO_COMMAND_SINDEX_FAILCODE(as_sindex_err_to_clienterr(res, __FILE__, __LINE__),
					as_sindex_err_str(res));
			goto ERR;
		}
	}

	cf_dyn_buf_append_string(db, "OK");
ERR:
	as_sindex_imd_free(&imd);
	return 0;
}

int
as_info_parse_ns_iname(char* params, as_namespace ** ns, char ** iname, cf_dyn_buf* db, char * sindex_cmd)
{
	char ns_str[AS_ID_NAMESPACE_SZ];
	int ns_len = sizeof(ns_str);
	int ret    = 0;

	ret = as_info_parameter_get(params, "ns", ns_str, &ns_len);
	if (ret) {
		if (ret == -2) {
			cf_warning(AS_INFO, "%s : namespace name exceeds max length %d",
				sindex_cmd, AS_ID_NAMESPACE_SZ);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Namespace name exceeds max length");
		}
		else {
			cf_warning(AS_INFO, "%s : invalid namespace %s", sindex_cmd, ns_str);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Namespace Not Specified");
		}
		return -1;
	}

	*ns = as_namespace_get_byname(ns_str);
	if (!*ns) {
		cf_warning(AS_INFO, "%s : namespace %s not found", sindex_cmd, ns_str);
		INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Namespace Not Found");
		return -1;
	}

	// get indexname
	char index_name_str[AS_ID_INAME_SZ];
	int  index_len = sizeof(index_name_str);
	ret = as_info_parameter_get(params, "indexname", index_name_str, &index_len);
	if (ret) {
		if (ret == -2) {
			cf_warning(AS_INFO, "%s : indexname exceeds max length %d", sindex_cmd, AS_ID_INAME_SZ);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Index Name exceeds max length");
		}
		else {
			cf_warning(AS_INFO, "%s : invalid indexname %s", sindex_cmd, index_name_str);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER,
				"Index Name Not Specified");
		}
		return -1;
	}

	cf_info(AS_SINDEX, "%s : received request on index %s - namespace %s",
			sindex_cmd, index_name_str, ns_str);

	*iname = cf_strdup(index_name_str);

	return 0;
}

int info_command_sindex_repair(char *name, char *params, cf_dyn_buf *db) {
	as_namespace *ns = NULL;
	char * iname = NULL;
	if (as_info_parse_ns_iname(params, &ns, &iname, db, "SINDEX REPAIR")) {
		return 0;
	}

	int resp = as_sindex_repair(ns, iname);
	if (resp) {
		cf_warning(AS_INFO, "Sindex repair failed for index %s: err = %d", name, resp);
		INFO_COMMAND_SINDEX_FAILCODE(as_sindex_err_to_clienterr(resp, __FILE__, __LINE__),
			as_sindex_err_str(resp));
		cf_warning(AS_INFO, "SINDEX REPAIR : for index %s - ns %s failed with error %d",
			iname, ns->name, resp);
	}
	else {
		cf_dyn_buf_append_string(db, "Ok");
	}

	if (iname) {
		cf_free(iname);
	}
	return(0);
}

int info_command_abort_scan(char *name, char *params, cf_dyn_buf *db) {
	char context[100];
	int  context_len = sizeof(context);
	int rv = -1;
	if (0 == as_info_parameter_get(params, "id", context, &context_len)) {
		uint64_t trid;
		trid = strtoull(context, NULL, 10);
		if (trid != 0) {
			rv = as_scan_abort(trid);
		}
	}

	if (rv != 0) {
		cf_dyn_buf_append_string(db, "ERROR:");
		cf_dyn_buf_append_int(db, AS_PROTO_RESULT_FAIL_NOTFOUND);
		cf_dyn_buf_append_string(db, ":Transaction Not Found");
	}
	else {
		cf_dyn_buf_append_string(db, "OK");
	}

	return 0;
}

int info_command_abort_all_scans(char *name, char *params, cf_dyn_buf *db) {

	int n_scans_killed = as_scan_abort_all();

	cf_dyn_buf_append_string(db, "OK - number of scans killed: ");
	cf_dyn_buf_append_int(db, n_scans_killed);

	return 0;
}

int info_command_query_kill(char *name, char *params, cf_dyn_buf *db) {
	char context[100];
	int  context_len = sizeof(context);
	int  rv          = AS_QUERY_ERR;
	if (0 == as_info_parameter_get(params, "trid", context, &context_len)) {
		uint64_t trid;
		trid = strtoull(context, NULL, 10);
		if (trid != 0) {
			rv = as_query_kill(trid);
		}
	}

	if (AS_QUERY_OK != rv) {
		cf_dyn_buf_append_string(db, "Transaction Not Found");
	}
	else {
		cf_dyn_buf_append_string(db, "Ok");
	}

	return 0;



}
int info_command_sindex_stat(char *name, char *params, cf_dyn_buf *db) {
	as_namespace  *ns = NULL;
	char * iname = NULL;

	if (as_info_parse_ns_iname(params, &ns, &iname, db, "SINDEX STAT")) {
		return 0;
	}

	int resp = as_sindex_stats_str(ns, iname, db);
	if (resp)  {
		cf_warning(AS_INFO, "SINDEX STAT : for index %s - ns %s failed with error %d",
			iname, ns->name, resp);
		INFO_COMMAND_SINDEX_FAILCODE(
				as_sindex_err_to_clienterr(resp, __FILE__, __LINE__),
				as_sindex_err_str(resp));
	}

	if (iname) {
		cf_free(iname);
	}
	return(0);
}


// sindex-histogram:ns=test_D;indexname=indname;enable=true/false
int info_command_sindex_histogram(char *name, char *params, cf_dyn_buf *db)
{
	as_namespace * ns = NULL;
	char * iname = NULL;
	if (as_info_parse_ns_iname(params, &ns, &iname, db, "SINDEX HISTOGRAM")) {
		return 0;
	}

	char op[10];
	int op_len = sizeof(op);

	if (as_info_parameter_get(params, "enable", op, &op_len)) {
		cf_info(AS_INFO, "SINDEX HISTOGRAM : invalid OP");
		cf_dyn_buf_append_string(db, "Invalid Op");
		goto END;
	}

	bool enable = false;
	if (!strncmp(op, "true", 5) && op_len != 5) {
		enable = true;
	}
	else if (!strncmp(op, "false", 6) && op_len != 6) {
		enable = false;
	}
	else {
		cf_info(AS_INFO, "SINDEX HISTOGRAM : invalid OP");
		cf_dyn_buf_append_string(db, "Invalid Op");
		goto END;
	}

	int resp = as_sindex_histogram_enable(ns, iname, enable);
	if (resp) {
		cf_warning(AS_INFO, "SINDEX HISTOGRAM : for index %s - ns %s failed with error %d",
			iname, ns->name, resp);
		INFO_COMMAND_SINDEX_FAILCODE(
				as_sindex_err_to_clienterr(resp, __FILE__, __LINE__),
				as_sindex_err_str(resp));
	} else {
		cf_dyn_buf_append_string(db, "Ok");
		cf_info(AS_INFO, "SINDEX HISTOGRAM : for index %s - ns %s histogram is set as %s",
			iname, ns->name, op);
	}

END:
	if (iname) {
		cf_free(iname);
	}
	return(0);
}

int info_command_sindex_list(char *name, char *params, cf_dyn_buf *db) {
	bool listall = true;
	char ns_str[128];
	int ns_len = sizeof(ns_str);
	if (!as_info_parameter_get(params, "ns", ns_str, &ns_len)) {
		listall = false;
	}

	if (listall) {
		bool found = 0;
		for (int i = 0; i < g_config.n_namespaces; i++) {
			as_namespace *ns = g_config.namespaces[i];
			if (ns) {
				if (!as_sindex_list_str(ns, db)) {
					found++;
				}
				else {
					cf_detail(AS_INFO, "No indexes for namespace %s", ns->name);
				}
			}
		}
		if (found == 0) {
			cf_dyn_buf_append_string(db, "Empty");
		}
		else {
			cf_dyn_buf_chomp(db);
		}
	}
	else {
		as_namespace *ns = as_namespace_get_byname(ns_str);
		if (!ns) {
			cf_warning(AS_INFO, "SINDEX LIST : ns %s not found", ns_str);
			INFO_COMMAND_SINDEX_FAILCODE(AS_PROTO_RESULT_FAIL_PARAMETER, "Namespace Not Found");
			return 0;
		} else {
			if (as_sindex_list_str(ns, db)) {
				cf_info(AS_INFO, "ns not found");
				cf_dyn_buf_append_string(db, "Empty");
			}
			return 0;
		}
	}
	return(0);
}

// Defined in "make_in/version.c" (auto-generated by the build system.)
extern const char aerospike_build_id[];
extern const char aerospike_build_time[];
extern const char aerospike_build_type[];
extern const char aerospike_build_os[];
extern const char aerospike_build_features[];

int
as_info_init()
{
	// g_info_node_info_history_hash is a hash of all nodes that have ever been
	// recognized by this node - either via paxos or info messages.
	shash_create(&g_info_node_info_history_hash, cf_nodeid_shash_fn, sizeof(cf_node), sizeof(info_node_info), 64, SHASH_CR_MT_BIGLOCK);

	// g_info_node_info_hash is a hash of all nodes *currently* in the cluster.
	// This hash should *always* be a subset of g_info_node_info_history_hash -
	// to ensure this, you should take the lock on the corresponding key in
	// info_history_hash before modifying an element in this hash table. This
	// hash is used to create the services list.
	shash_create(&g_info_node_info_hash, cf_nodeid_shash_fn, sizeof(cf_node), sizeof(info_node_info), 64, SHASH_CR_MT_BIGLOCK);

	// create worker threads
	g_info_work_q = cf_queue_create(sizeof(as_info_transaction), true);

	char vstr[64];
	sprintf(vstr, "%s build %s", aerospike_build_type, aerospike_build_id);

	// Set some basic values
	as_info_set("version", vstr, true);                  // Returns the edition and build number.
	as_info_set("build", aerospike_build_id, true);      // Returns the build number for this server.
	as_info_set("build_os", aerospike_build_os, true);   // Return the OS used to create this build.
	as_info_set("build_time", aerospike_build_time, true); // Return the creation time of this build.
	as_info_set("edition", aerospike_build_type, true);  // Return the edition of this build.
	as_info_set("digests", "RIPEMD160", false);          // Returns the hashing algorithm used by the server for key hashing.
	as_info_set("status", "ok", false);                  // Always returns ok, used to verify service port is open.
	as_info_set("STATUS", "OK", false);                  // Always returns OK, used to verify service port is open.

	char istr[64];
	cf_str_itoa(AS_PARTITIONS, istr, 10);
	as_info_set("partitions", istr, false);              // Returns the number of partitions used to hash keys across.

	cf_str_itoa_u64(g_config.self_node, istr, 16);
	as_info_set("node", istr, true);                     // Node ID. Unique 15 character hex string for each node based on the mac address and port.
	as_info_set("name", istr, false);                    // Alias to 'node'.
	// Returns list of features supported by this server
	static char features[1024];
	strcat(features, "cdt-list;cdt-map;pipelining;geo;float;batch-index;replicas-all;replicas-master;replicas-prole;udf");
	strcat(features, aerospike_build_features);
	as_info_set("features", features, true);
	hb_mode_enum hb_mode;
	as_hb_info_listen_addr_get(&hb_mode, istr);
	as_info_set( hb_mode == AS_HB_MODE_MESH ? "mesh" :  "mcast", istr, false);

	// All commands accepted by asinfo/telnet
	as_info_set("help", "alloc-info;asm;bins;build;build_os;build_time;config-get;config-set;"
				"df;digests;dump-fabric;dump-hb;dump-migrates;dump-msgs;dump-paxos;dump-rw;"
				"dump-smd;dump-wb;dump-wb-summary;get-config;get-sl;hist-dump;"
				"hist-track-start;hist-track-stop;jem-stats;jobs;latency;log;log-set;"
				"log-message;logs;mcast;mem;mesh;mstats;mtrace;name;namespace;namespaces;node;"
				"service;services;services-alumni;services-alumni-reset;set-config;"
				"set-log;sets;set-sl;show-devices;sindex;sindex-create;sindex-delete;"
				"sindex-histogram;sindex-repair;"
				"smd;statistics;status;tip;tip-clear;version;"
				"xdr-min-lastshipinfo",
				false);
	/*
	 * help intentionally does not include the following:
	 * cluster-generation;features;objects;
	 * partition-generation;partition-info;partitions;replicas-master;
	 * replicas-prole;replicas-read;replicas-write;throughput
	 */

	// Set up some dynamic functions
	as_info_set_dynamic("bins", info_get_bins, false);                                // Returns bin usage information and used bin names.
	as_info_set_dynamic("cluster-generation", info_get_cluster_generation, true);     // Returns cluster generation.
	as_info_set_dynamic("get-config", info_get_config, false);                        // Returns running config for specified context.
	as_info_set_dynamic("logs", info_get_logs, false);                                // Returns a list of log file locations in use by this server.
	as_info_set_dynamic("namespaces", info_get_namespaces, false);                    // Returns a list of namespace defined on this server.
	as_info_set_dynamic("objects", info_get_objects, false);                          // Returns the number of objects stored on this server.
	as_info_set_dynamic("partition-generation", info_get_partition_generation, true); // Returns the current partition generation.
	as_info_set_dynamic("partition-info", info_get_partition_info, false);            // Returns partition ownership information.
	as_info_set_dynamic("replicas-all", info_get_replicas_all, false);                // Base 64 encoded binary representation of partitions this node is replica for.
	as_info_set_dynamic("replicas-master", info_get_replicas_master, false);          // Base 64 encoded binary representation of partitions this node is master (replica) for.
	as_info_set_dynamic("replicas-prole", info_get_replicas_prole, false);            // Base 64 encoded binary representation of partitions this node is prole (replica) for.
	as_info_set_dynamic("replicas-read", info_get_replicas_read, false);              //
	as_info_set_dynamic("replicas-write", info_get_replicas_write, false);            //
	as_info_set_dynamic("service", info_get_service, false);                          // IP address and server port for this node, expected to be a single.
	                                                                                  // address/port per node, may be multiple address if this node is configured.
	                                                                                  // to listen on multiple interfaces (typically not advised).
	as_info_set_dynamic("services", info_get_services, true);                         // List of addresses of neighbor cluster nodes to advertise for Application to connect.
	as_info_set_dynamic("services-alternate", info_get_alt_addr, false);              // IP address mapping from internal to public ones
	as_info_set_dynamic("services-alumni", info_get_services_alumni, true);           // All neighbor addresses (services) this server has ever know about.
	as_info_set_dynamic("services-alumni-reset", info_services_alumni_reset, false);  // Reset the services alumni to equal services
	as_info_set_dynamic("sets", info_get_sets, false);                                // Returns set statistics for all or a particular set.
	as_info_set_dynamic("statistics", info_get_stats, true);                          // Returns system health and usage stats for this server.
	as_info_set_dynamic("switch-hb-v3", info_command_set_hb_protocol_v3, false);      // Set heartbeat protocol to v3(Temporary for testing v3).

#ifdef INFO_SEGV_TEST
	as_info_set_dynamic("segvtest", info_segv_test, true);
#endif

	// Tree-based names
	as_info_set_tree("bins", info_get_tree_bins);           // Returns bin usage information and used bin names for all or a particular namespace.
	as_info_set_tree("log", info_get_tree_log);             //
	as_info_set_tree("namespace", info_get_tree_namespace); // Returns health and usage stats for a particular namespace.
	as_info_set_tree("sets", info_get_tree_sets);           // Returns set statistics for all or a particular set.

	// Define commands
	as_info_set_command("alloc-info", info_command_alloc_info, PERM_NONE);                    // Lookup a memory allocation by program location.
	as_info_set_command("asm", info_command_asm, PERM_SERVICE_CTRL);                          // Control the operation of the ASMalloc library.
	as_info_set_command("config-get", info_command_config_get, PERM_NONE);                    // Returns running config for specified context.
	as_info_set_command("config-set", info_command_config_set, PERM_SET_CONFIG);              // Set a configuration parameter at run time, configuration parameter must be dynamic.
	as_info_set_command("df", info_command_double_free, PERM_SERVICE_CTRL);                   // Do an intentional double "free()" to test Double "free()" Detection.
	as_info_set_command("dump-fabric", info_command_dump_fabric, PERM_LOGGING_CTRL);          // Print debug information about fabric to the log file.
	as_info_set_command("dump-hb", info_command_dump_hb, PERM_LOGGING_CTRL);                  // Print debug information about heartbeat state to the log file.
	as_info_set_command("dump-hlc", info_command_dump_hlc, PERM_LOGGING_CTRL);                // Print debug information about Hybrid Logical Clock to the log file.
	as_info_set_command("dump-migrates", info_command_dump_migrates, PERM_LOGGING_CTRL);      // Print debug information about migration.
	as_info_set_command("dump-msgs", info_command_dump_msgs, PERM_LOGGING_CTRL);              // Print debug information about existing 'msg' objects and queues to the log file.
	as_info_set_command("dump-paxos", info_command_dump_paxos, PERM_LOGGING_CTRL);            // Print debug information about Paxos state to the log file.
	as_info_set_command("dump-ra", info_command_dump_ra, PERM_LOGGING_CTRL);                  // Print debug information about Rack Aware state.
	as_info_set_command("dump-rw", info_command_dump_rw_request_hash, PERM_LOGGING_CTRL);     // Print debug information about transaction hash table to the log file.
	as_info_set_command("dump-smd", info_command_dump_smd, PERM_LOGGING_CTRL);                // Print information about System Metadata (SMD) to the log file.
	as_info_set_command("dump-wb", info_command_dump_wb, PERM_LOGGING_CTRL);                  // Print debug information about Write Bocks (WB) to the log file.
	as_info_set_command("dump-wb-summary", info_command_dump_wb_summary, PERM_LOGGING_CTRL);  // Print summary information about all Write Blocks (WB) on a device to the log file.
	as_info_set_command("get-config", info_command_config_get, PERM_NONE);                    // Returns running config for all or a particular context.
	as_info_set_command("get-sl", info_command_get_sl, PERM_NONE);                            // Get the Paxos succession list.
	as_info_set_command("hist-dump", info_command_hist_dump, PERM_NONE);                      // Returns a histogram snapshot for a particular histogram.
	as_info_set_command("hist-track-start", info_command_hist_track, PERM_SERVICE_CTRL);      // Start or Restart histogram tracking.
	as_info_set_command("hist-track-stop", info_command_hist_track, PERM_SERVICE_CTRL);       // Stop histogram tracking.
	as_info_set_command("jem-stats", info_command_jem_stats, PERM_LOGGING_CTRL);              // Print JEMalloc statistics to the log file.
	as_info_set_command("latency", info_command_hist_track, PERM_NONE);                       // Returns latency and throughput information.
	as_info_set_command("log-message", info_command_log_message, PERM_NONE);                  // Log a message.
	as_info_set_command("log-set", info_command_log_set, PERM_LOGGING_CTRL);                  // Set values in the log system.
	as_info_set_command("mem", info_command_mem, PERM_NONE);                                  // Report on memory usage.
	as_info_set_command("mstats", info_command_mstats, PERM_LOGGING_CTRL);                    // Dump GLibC-level memory stats.
	as_info_set_command("mtrace", info_command_mtrace, PERM_SERVICE_CTRL);                    // Control GLibC-level memory tracing.
	as_info_set_command("set-config", info_command_config_set, PERM_SET_CONFIG);              // Set config values.
	as_info_set_command("set-log", info_command_log_set, PERM_LOGGING_CTRL);                  // Set values in the log system.
	as_info_set_command("show-devices", info_command_show_devices, PERM_LOGGING_CTRL);        // Print snapshot of wblocks to the log file.
	as_info_set_command("smd", info_command_smd_cmd, PERM_SERVICE_CTRL);                      // Manipulate the System Metadata.
	as_info_set_command("throughput", info_command_hist_track, PERM_NONE);                    // Returns throughput info.
	as_info_set_command("tip", info_command_tip, PERM_SERVICE_CTRL);                          // Add external IP to mesh-mode heartbeats.
	as_info_set_command("tip-clear", info_command_tip_clear, PERM_SERVICE_CTRL);              // Clear tip list from mesh-mode heartbeats.
	as_info_set_command("xdr-command", as_info_command_xdr, PERM_SERVICE_CTRL);               // Command to XDR module.

	// SINDEX
	as_info_set_dynamic("sindex", info_get_sindexes, false);
	as_info_set_tree("sindex", info_get_tree_sindexes);
	as_info_set_command("sindex-create", info_command_sindex_create, PERM_INDEX_MANAGE);  // Create a secondary index.
	as_info_set_command("sindex-delete", info_command_sindex_delete, PERM_INDEX_MANAGE);  // Delete a secondary index.

	// UDF
	as_info_set_dynamic("udf-list", udf_cask_info_list, false);
	as_info_set_command("udf-put", udf_cask_info_put, PERM_UDF_MANAGE);
	as_info_set_command("udf-get", udf_cask_info_get, PERM_NONE);
	as_info_set_command("udf-remove", udf_cask_info_remove, PERM_UDF_MANAGE);
	as_info_set_command("udf-clear-cache", udf_cask_info_clear_cache, PERM_UDF_MANAGE);

	// JOBS
	as_info_set_command("jobs", info_command_mon_cmd, PERM_JOB_MONITOR);  // Manipulate the multi-key lookup monitoring infrastructure.

	// Undocumented Secondary Index Command
	as_info_set_command("sindex-histogram", info_command_sindex_histogram, PERM_SERVICE_CTRL);
	as_info_set_command("sindex-repair", info_command_sindex_repair, PERM_SERVICE_CTRL);

	as_info_set_dynamic("query-list", as_query_list, false);
	as_info_set_command("query-kill", info_command_query_kill, PERM_QUERY_MANAGE);
	as_info_set_command("scan-abort", info_command_abort_scan, PERM_SCAN_MANAGE);            // Abort a scan with a given id.
	as_info_set_command("scan-abort-all", info_command_abort_all_scans, PERM_SCAN_MANAGE);   // Abort all scans.
	as_info_set_dynamic("scan-list", as_scan_list, false);                                   // List info for all scan jobs.
	as_info_set_command("sindex-stat", info_command_sindex_stat, PERM_NONE);
	as_info_set_command("sindex-list", info_command_sindex_list, PERM_NONE);
	as_info_set_dynamic("sindex-builder-list", as_sbld_list, false);                         // List info for all secondary index builder jobs.

	as_xdr_info_init();

	// Spin up the Info threads *after* all static and dynamic Info commands have been added
	// so we can guarantee that the static and dynamic lists will never again be changed.
	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);

	for (int i = 0; i < g_config.n_info_threads; i++) {
		pthread_t tid;
		if (0 != pthread_create(&tid, &thr_attr, thr_info_fn, (void *) 0 )) {
			cf_crash(AS_INFO, "pthread_create: %s", cf_strerror(errno));
		}
	}

	as_fabric_register_msg_fn(M_TYPE_INFO, info_mt, sizeof(info_mt), INFO_MSG_SCRATCH_SIZE, info_msg_fn, 0 /* udata */ );

	pthread_t info_interfaces_th;
	// if there's a statically configured external interface, use this simple function to monitor
	// and transmit
	if (g_config.external_address) {
		pthread_create(&info_interfaces_th, &thr_attr, info_interfaces_static_fn, 0);
	} else {
		// Or if we've got interfaces, monitor and transmit
		pthread_create(&info_interfaces_th, &thr_attr, info_interfaces_fn, 0);
	}

	return(0);
}
