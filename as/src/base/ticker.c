/*
 * ticker.c
 *
 * Copyright (C) 2016 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include "base/ticker.h"

#include <malloc.h>
#include <mcheck.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/param.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"

#include "dynbuf.h"
#include "fault.h"
#include "hist.h"
#include "hist_track.h"
#include "jem.h"
#include "meminfo.h"

#include "base/asm.h"
#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/secondary_index.h"
#include "base/stats.h"
#include "base/thr_info.h"
#include "base/thr_sindex.h"
#include "base/thr_tsvc.h"
#include "fabric/fabric.h"
#include "fabric/hb.h"
#include "fabric/paxos.h"
#include "storage/storage.h"
#include "transaction/proxy.h"
#include "transaction/rw_request_hash.h"


//==========================================================
// Forward Declarations.
//

extern int as_nsup_queue_get_size();
extern bool g_shutdown_started;

void* run_ticker(void* arg);
void log_ticker_frame();

void log_line_system_memory();
void log_line_in_progress();
void log_line_fds();
void log_line_heartbeat();
void log_line_early_fail();
void log_line_batch_index();

void log_line_objects(as_namespace* ns, uint64_t n_objects,
		uint64_t n_sub_objects);
void log_line_migrations(as_namespace* ns);
void log_line_memory_usage(as_namespace* ns, size_t total_mem, size_t index_mem,
		size_t sindex_mem, size_t data_mem);
void log_line_device_usage(as_namespace* ns);
void log_line_ldt_gc(as_namespace* ns);

void log_line_client(as_namespace* ns);
void log_line_batch_sub(as_namespace* ns);
void log_line_scan(as_namespace* ns);
void log_line_query(as_namespace* ns);
void log_line_udf_sub(as_namespace* ns);

void dump_global_histograms();
void dump_namespace_histograms(as_namespace* ns);

void log_mem_stats(size_t total_ns_memory_inuse);


//==========================================================
// Public API.
//

void
as_ticker_start()
{
	pthread_t thread;
	pthread_attr_t attrs;

	pthread_attr_init(&attrs);
	pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&thread, &attrs, run_ticker, NULL) != 0) {
		cf_crash(AS_INFO, "failed to create ticker thread");
	}
}


//==========================================================
// Local helpers.
//

void*
run_ticker(void* arg)
{
	uint64_t last_time = cf_getns();

	while (true) {
		// Wake up every 1 second to check the ticker interval.
		struct timespec delay = { 1, 0 };
		nanosleep(&delay, NULL);

		uint64_t curr_time = cf_getns();

		if (curr_time - last_time <
				(uint64_t)g_config.ticker_interval * 1000000000) {
			continue; // period has not been reached for showing a frame
		}

		last_time = curr_time;

		// Reduce likelihood of ticker frames showing after shutdown signal.
		if (g_shutdown_started) {
			break;
		}

		log_ticker_frame();
	}

	return NULL;
}


void
log_ticker_frame()
{
	cf_info(AS_INFO, "NODE-ID %lx CLUSTER-SIZE %zd",
			g_config.self_node,
			g_paxos->cluster_size
			);

	log_line_system_memory();
	log_line_in_progress();
	log_line_fds();
	log_line_heartbeat();
	log_line_early_fail();
	log_line_batch_index();

	dump_global_histograms();

	size_t total_ns_memory_inuse = 0;

	for (int i = 0; i < g_config.n_namespaces; i++) {
		as_namespace* ns = g_config.namespaces[i];

		uint64_t n_objects = ns->n_objects;
		uint64_t n_sub_objects = ns->n_sub_objects;

		size_t index_mem = as_index_size_get(ns) * (n_objects + n_sub_objects);
		size_t sindex_mem = ns->sindex_data_memory_used;
		size_t data_mem = ns->n_bytes_memory;
		size_t total_mem = index_mem + sindex_mem + data_mem;

		total_ns_memory_inuse += total_mem;

		log_line_objects(ns, n_objects, n_sub_objects);
		log_line_migrations(ns);
		log_line_memory_usage(ns, total_mem, index_mem, sindex_mem, data_mem);
		log_line_device_usage(ns);
		log_line_ldt_gc(ns);

		log_line_client(ns);
		log_line_batch_sub(ns);
		log_line_scan(ns);
		log_line_query(ns);
		log_line_udf_sub(ns);

		dump_namespace_histograms(ns);
	}

	log_mem_stats(total_ns_memory_inuse);

	if (g_config.fabric_dump_msgs) {
		as_fabric_msg_queue_dump();
	}
}


void
log_line_system_memory()
{
	uint64_t freemem;
	int freepct;
	bool swapping;

	cf_meminfo(0, &freemem, &freepct, &swapping);

	cf_info(AS_INFO, "   system-memory: free-kbytes %lu free-pct %d%s",
			freemem / 1024,
			freepct,
			swapping ? " SWAPPING!" : ""
			);
}


void
log_line_in_progress()
{
	cf_info(AS_INFO, "   in-progress: tsvc-q %d info-q %d nsup-delete-q %d rw-hash %u proxy-hash %u rec-refs %lu",
			thr_tsvc_queue_get_size(),
			as_info_queue_get_size(),
			as_nsup_queue_get_size(),
			rw_request_hash_count(),
			as_proxy_hash_count(),
			g_stats.global_record_ref_count
			);
}


void
log_line_fds()
{
	uint64_t n_proto_fds_opened = g_stats.proto_connections_opened;
	uint64_t n_proto_fds_closed = g_stats.proto_connections_closed;
	uint64_t n_hb_fds_opened = g_stats.heartbeat_connections_opened;
	uint64_t n_hb_fds_closed = g_stats.heartbeat_connections_closed;
	uint64_t n_fabric_fds_opened = g_stats.fabric_connections_opened;
	uint64_t n_fabric_fds_closed = g_stats.fabric_connections_closed;

	uint64_t n_proto_fds_open = n_proto_fds_opened - n_proto_fds_closed;
	uint64_t n_hb_fds_open = n_hb_fds_opened - n_hb_fds_closed;
	uint64_t n_fabric_fds_open = n_fabric_fds_opened - n_fabric_fds_closed;

	cf_info(AS_INFO, "   fds: proto (%lu,%lu,%lu) heartbeat (%lu,%lu,%lu) fabric (%lu,%lu,%lu)",
			n_proto_fds_open, n_proto_fds_opened, n_proto_fds_closed,
			n_hb_fds_open, n_hb_fds_opened, n_hb_fds_closed,
			n_fabric_fds_open, n_fabric_fds_opened, n_fabric_fds_closed
			);
}


void
log_line_heartbeat()
{
	cf_info(AS_INFO, "   heartbeat-received: self %lu foreign %lu",
			g_stats.heartbeat_received_self, g_stats.heartbeat_received_foreign
			);
}


void
log_line_early_fail()
{
	uint64_t n_demarshal = g_stats.n_demarshal_error;
	uint64_t n_tsvc_client = g_stats.n_tsvc_client_error;
	uint64_t n_tsvc_batch_sub = g_stats.n_tsvc_batch_sub_error;
	uint64_t n_tsvc_udf_sub = g_stats.n_tsvc_udf_sub_error;

	if ((n_demarshal |
			n_tsvc_client |
			n_tsvc_batch_sub |
			n_tsvc_udf_sub) == 0) {
		return;
	}

	cf_info(AS_INFO, "   early-fail: demarshal %lu tsvc-client %lu tsvc-batch-sub %lu tsvc-udf-sub %lu",
			n_demarshal,
			n_tsvc_client,
			n_tsvc_batch_sub,
			n_tsvc_udf_sub
			);
}


void
log_line_batch_index()
{
	uint64_t n_complete = g_stats.batch_index_complete;
	uint64_t n_error = g_stats.batch_index_errors;
	uint64_t n_timeout = g_stats.batch_index_timeout;

	if ((n_complete | n_error | n_timeout) == 0) {
		return;
	}

	cf_info(AS_INFO, "   batch-index: batches (%lu,%lu,%lu)",
			n_complete, n_error, n_timeout
			);
}


void
log_line_objects(as_namespace* ns, uint64_t n_objects, uint64_t n_sub_objects)
{
	as_master_prole_stats mp;
	as_partition_get_master_prole_stats(ns, &mp);

	// TODO - show if all 0's ???
	cf_info(AS_INFO, "{%s} objects: all %lu master %lu prole %lu",
			ns->name,
			n_objects,
			mp.n_master_records,
			mp.n_prole_records
			);

	if ((n_sub_objects |
			mp.n_master_sub_records |
			mp.n_prole_sub_records) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} sub-objects: all %lu master %lu prole %lu",
			ns->name,
			n_sub_objects,
			mp.n_master_sub_records,
			mp.n_prole_sub_records
			);
}


void
log_line_migrations(as_namespace* ns)
{
	int64_t initial_rx = (int64_t)ns->migrate_rx_partitions_initial;
	int64_t initial_tx = (int64_t)ns->migrate_tx_partitions_initial;
	int64_t remaining_rx = (int64_t)ns->migrate_rx_partitions_remaining;
	int64_t remaining_tx = (int64_t)ns->migrate_tx_partitions_remaining;
	int64_t initial = initial_rx + initial_tx;
	int64_t remaining = remaining_rx + remaining_tx;

	if (initial > 0 && remaining > 0) {
		float complete_pct = (1 - ((float)remaining / (float)initial)) * 100;

		cf_info(AS_INFO, "{%s} migrations: remaining (%ld,%ld) active (%ld,%ld) complete-pct %0.2f",
				ns->name,
				remaining_tx, remaining_rx,
				ns->migrate_tx_partitions_active, ns->migrate_rx_partitions_active,
				complete_pct
				);
	}
	else {
		cf_info(AS_INFO, "{%s} migrations: complete", ns->name);
	}
}


void
log_line_memory_usage(as_namespace* ns, size_t total_mem, size_t index_mem,
		size_t sindex_mem, size_t data_mem)
{
	double mem_used_pct = (double)(total_mem * 100) / (double)ns->memory_size;

	if (ns->storage_data_in_memory) {
		cf_info(AS_INFO, "{%s} memory-usage: total-bytes %lu index-bytes %lu sindex-bytes %lu data-bytes %lu used-pct %.2lf",
				ns->name,
				total_mem,
				index_mem,
				sindex_mem,
				data_mem,
				mem_used_pct
				);
	}
	else {
		cf_info(AS_INFO, "{%s} memory-usage: total-bytes %lu index-bytes %lu sindex-bytes %lu used-pct %.2lf",
				ns->name,
				total_mem,
				index_mem,
				sindex_mem,
				mem_used_pct
				);
	}
}


void
log_line_device_usage(as_namespace* ns)
{
	if (ns->storage_type != AS_STORAGE_ENGINE_SSD) {
		return;
	}

	int available_pct;
	uint64_t inuse_disk_bytes;
	as_storage_stats(ns, &available_pct, &inuse_disk_bytes);

	if (ns->storage_data_in_memory) {
		cf_info(AS_INFO, "{%s} device-usage: used-bytes %lu avail-pct %d",
				ns->name,
				inuse_disk_bytes,
				available_pct
				);
	}
	else {
		uint32_t n_reads_from_cache = ns->n_reads_from_cache;
		uint32_t n_total_reads = ns->n_reads_from_device + n_reads_from_cache;

		cf_atomic32_set(&ns->n_reads_from_device, 0);
		cf_atomic32_set(&ns->n_reads_from_cache, 0);

		ns->cache_read_pct =
				(float)(100 * n_reads_from_cache) /
				(float)(n_total_reads == 0 ? 1 : n_total_reads);

		cf_info(AS_INFO, "{%s} device-usage: used-bytes %lu avail-pct %d cache-read-pct %.2f",
				ns->name,
				inuse_disk_bytes,
				available_pct,
				ns->cache_read_pct
				);
	}
}


void
log_line_ldt_gc(as_namespace* ns)
{
	if (! ns->ldt_enabled) {
		return;
	}

	uint64_t cnt = ns->lstats.ldt_gc_processed;
	uint64_t io = ns->lstats.ldt_gc_io;
	uint64_t gc = ns->lstats.ldt_gc_cnt;
	uint64_t no_esr = ns->lstats.ldt_gc_no_esr_cnt;
	uint64_t no_parent = ns->lstats.ldt_gc_no_parent_cnt;
	uint64_t version_mismatch = ns->lstats.ldt_gc_parent_version_mismatch_cnt;

	cf_info(AS_INFO, "{%s} ldt-gc: cnt %lu io %lu gc %lu (%lu,%lu,%lu)",
			ns->name,
			cnt,
			io,
			gc,
			no_esr, no_parent, version_mismatch
			);
}


void
log_line_client(as_namespace* ns)
{
	uint64_t n_tsvc_error = ns->n_client_tsvc_error;
	uint64_t n_tsvc_timeout = ns->n_client_tsvc_timeout;
	uint64_t n_proxy_complete = ns->n_client_proxy_complete;
	uint64_t n_proxy_error = ns->n_client_proxy_error;
	uint64_t n_proxy_timeout = ns->n_client_proxy_timeout;
	uint64_t n_read_success = ns->n_client_read_success;
	uint64_t n_read_error = ns->n_client_read_error;
	uint64_t n_read_timeout = ns->n_client_read_timeout;
	uint64_t n_read_not_found = ns->n_client_read_not_found;
	uint64_t n_write_success = ns->n_client_write_success;
	uint64_t n_write_error = ns->n_client_write_error;
	uint64_t n_write_timeout = ns->n_client_write_timeout;
	uint64_t n_delete_success = ns->n_client_delete_success;
	uint64_t n_delete_error = ns->n_client_delete_error;
	uint64_t n_delete_timeout = ns->n_client_delete_timeout;
	uint64_t n_delete_not_found = ns->n_client_delete_not_found;
	uint64_t n_udf_complete = ns->n_client_udf_complete;
	uint64_t n_udf_error = ns->n_client_udf_error;
	uint64_t n_udf_timeout = ns->n_client_udf_timeout;
	uint64_t n_lang_read_success = ns->n_client_lang_read_success;
	uint64_t n_lang_write_success = ns->n_client_lang_write_success;
	uint64_t n_lang_delete_success = ns->n_client_lang_delete_success;
	uint64_t n_lang_error = ns->n_client_lang_error;

	if ((n_tsvc_error | n_tsvc_timeout |
			n_proxy_complete | n_proxy_error | n_proxy_timeout |
			n_read_success | n_read_error | n_read_timeout | n_read_not_found |
			n_write_success | n_write_error | n_write_timeout |
			n_delete_success | n_delete_error | n_delete_timeout | n_delete_not_found |
			n_udf_complete | n_udf_error | n_udf_timeout |
			n_lang_read_success | n_lang_write_success | n_lang_delete_success | n_lang_error) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} client: tsvc (%lu,%lu) proxy (%lu,%lu,%lu) read (%lu,%lu,%lu,%lu) write (%lu,%lu,%lu) delete (%lu,%lu,%lu,%lu) udf (%lu,%lu,%lu) lang (%lu,%lu,%lu,%lu)",
			ns->name,
			n_tsvc_error, n_tsvc_timeout,
			n_proxy_complete, n_proxy_error, n_proxy_timeout,
			n_read_success, n_read_error, n_read_timeout, n_read_not_found,
			n_write_success, n_write_error, n_write_timeout,
			n_delete_success, n_delete_error, n_delete_timeout, n_delete_not_found,
			n_udf_complete, n_udf_error, n_udf_timeout,
			n_lang_read_success, n_lang_write_success, n_lang_delete_success, n_lang_error
			);
}


void
log_line_batch_sub(as_namespace* ns)
{
	uint64_t n_tsvc_error = ns->n_batch_sub_tsvc_error;
	uint64_t n_tsvc_timeout = ns->n_batch_sub_tsvc_timeout;
	uint64_t n_proxy_complete = ns->n_batch_sub_proxy_complete;
	uint64_t n_proxy_error = ns->n_batch_sub_proxy_error;
	uint64_t n_proxy_timeout = ns->n_batch_sub_proxy_timeout;
	uint64_t n_read_success = ns->n_batch_sub_read_success;
	uint64_t n_read_error = ns->n_batch_sub_read_error;
	uint64_t n_read_timeout = ns->n_batch_sub_read_timeout;
	uint64_t n_read_not_found = ns->n_batch_sub_read_not_found;

	if ((n_tsvc_error | n_tsvc_timeout |
			n_proxy_complete | n_proxy_error | n_proxy_timeout |
			n_read_success | n_read_error | n_read_timeout | n_read_not_found) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} batch-sub: tsvc (%lu,%lu) proxy (%lu,%lu,%lu) read (%lu,%lu,%lu,%lu)",
			ns->name,
			n_tsvc_error, n_tsvc_timeout,
			n_proxy_complete, n_proxy_error, n_proxy_timeout,
			n_read_success, n_read_error, n_read_timeout, n_read_not_found
			);
}


void
log_line_scan(as_namespace* ns)
{
	uint64_t n_basic_complete = ns->n_scan_basic_complete;
	uint64_t n_basic_error = ns->n_scan_basic_error;
	uint64_t n_basic_abort = ns->n_scan_basic_abort;
	uint64_t n_aggr_complete = ns->n_scan_aggr_complete;
	uint64_t n_aggr_error = ns->n_scan_aggr_error;
	uint64_t n_aggr_abort = ns->n_scan_aggr_abort;
	uint64_t n_udf_bg_complete = ns->n_scan_udf_bg_complete;
	uint64_t n_udf_bg_error = ns->n_scan_udf_bg_error;
	uint64_t n_udf_bg_abort = ns->n_scan_udf_bg_abort;

	if ((n_basic_complete | n_basic_error | n_basic_abort |
			n_aggr_complete | n_aggr_error | n_aggr_abort |
			n_udf_bg_complete | n_udf_bg_error | n_udf_bg_abort) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} scan: basic (%lu,%lu,%lu) aggr (%lu,%lu,%lu) udf-bg (%lu,%lu,%lu)",
			ns->name,
			n_basic_complete, n_basic_error, n_basic_abort,
			n_aggr_complete, n_aggr_error, n_aggr_abort,
			n_udf_bg_complete, n_udf_bg_error, n_udf_bg_abort
			);
}


void
log_line_query(as_namespace* ns)
{
	uint64_t n_basic_success = ns->n_lookup_success;
	uint64_t n_basic_failure = ns->n_lookup_errs + ns->n_lookup_abort;
	uint64_t n_aggr_success = ns->n_agg_success;
	uint64_t n_aggr_failure = ns->n_agg_errs + ns->n_agg_abort;
	uint64_t n_udf_bg_success = ns->n_query_udf_bg_success;
	uint64_t n_udf_bg_failure = ns->n_query_udf_bg_failure;

	if ((n_basic_success | n_basic_failure |
			n_aggr_success | n_aggr_failure |
			n_udf_bg_success | n_udf_bg_failure) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} query: basic (%lu,%lu) aggr (%lu,%lu) udf-bg (%lu,%lu)",
			ns->name,
			n_basic_success, n_basic_failure,
			n_aggr_success, n_aggr_failure,
			n_udf_bg_success, n_udf_bg_failure
			);
}


void
log_line_udf_sub(as_namespace* ns)
{
	uint64_t n_tsvc_error = ns->n_udf_sub_tsvc_error;
	uint64_t n_tsvc_timeout = ns->n_udf_sub_tsvc_timeout;
	uint64_t n_udf_complete = ns->n_udf_sub_udf_complete;
	uint64_t n_udf_error = ns->n_udf_sub_udf_error;
	uint64_t n_udf_timeout = ns->n_udf_sub_udf_timeout;
	uint64_t n_lang_read_success = ns->n_udf_sub_lang_read_success;
	uint64_t n_lang_write_success = ns->n_udf_sub_lang_write_success;
	uint64_t n_lang_delete_success = ns->n_udf_sub_lang_delete_success;
	uint64_t n_lang_error = ns->n_udf_sub_lang_error;

	if ((n_tsvc_error | n_tsvc_timeout |
			n_udf_complete | n_udf_error | n_udf_timeout |
			n_lang_read_success | n_lang_write_success | n_lang_delete_success | n_lang_error) == 0) {
		return;
	}

	cf_info(AS_INFO, "{%s} udf-sub: tsvc (%lu,%lu) udf (%lu,%lu,%lu) lang (%lu,%lu,%lu,%lu)",
			ns->name,
			n_tsvc_error, n_tsvc_timeout,
			n_udf_complete, n_udf_error, n_udf_timeout,
			n_lang_read_success, n_lang_write_success, n_lang_delete_success, n_lang_error
			);
}


void
dump_global_histograms()
{
	if (g_stats.batch_index_hist_active) {
		histogram_dump(g_stats.batch_index_hist);
	}

	if (g_config.info_hist_enabled) {
		histogram_dump(g_stats.info_hist);
	}

	if (g_config.svc_benchmarks_enabled) {
		histogram_dump(g_stats.svc_demarshal_hist);
		histogram_dump(g_stats.svc_queue_hist);
	}

	as_query_histogram_dumpall();
	as_sindex_gc_histogram_dumpall();

	if (g_config.ldt_benchmarks) {
		histogram_dump(g_stats.ldt_multiop_prole_hist);
		histogram_dump(g_stats.ldt_update_record_cnt_hist);
		histogram_dump(g_stats.ldt_io_record_cnt_hist);
		histogram_dump(g_stats.ldt_update_io_bytes_hist);
		histogram_dump(g_stats.ldt_hist);
	}
}


void
dump_namespace_histograms(as_namespace* ns)
{
	if (ns->read_hist_active) {
		cf_hist_track_dump(ns->read_hist);
	}

	if (ns->read_benchmarks_enabled) {
		histogram_dump(ns->read_start_hist);
		histogram_dump(ns->read_restart_hist);
		histogram_dump(ns->read_dup_res_hist);
		histogram_dump(ns->read_local_hist);
		histogram_dump(ns->read_response_hist);
	}

	if (ns->write_hist_active) {
		cf_hist_track_dump(ns->write_hist);
	}

	if (ns->write_benchmarks_enabled) {
		histogram_dump(ns->write_start_hist);
		histogram_dump(ns->write_restart_hist);
		histogram_dump(ns->write_dup_res_hist);
		histogram_dump(ns->write_master_hist);
		histogram_dump(ns->write_repl_write_hist);
		histogram_dump(ns->write_response_hist);
	}

	if (ns->udf_hist_active) {
		cf_hist_track_dump(ns->udf_hist);
	}

	if (ns->udf_benchmarks_enabled) {
		histogram_dump(ns->udf_start_hist);
		histogram_dump(ns->udf_restart_hist);
		histogram_dump(ns->udf_dup_res_hist);
		histogram_dump(ns->udf_master_hist);
		histogram_dump(ns->udf_repl_write_hist);
		histogram_dump(ns->udf_response_hist);
	}

	if (ns->query_hist_active) {
		cf_hist_track_dump(ns->query_hist);
	}

	if (ns->query_rec_count_hist_active) {
		histogram_dump(ns->query_rec_count_hist);
	}

	if (ns->proxy_hist_enabled) {
		histogram_dump(ns->proxy_hist);
	}

	if (ns->batch_sub_benchmarks_enabled) {
		histogram_dump(ns->batch_sub_start_hist);
		histogram_dump(ns->batch_sub_restart_hist);
		histogram_dump(ns->batch_sub_dup_res_hist);
		histogram_dump(ns->batch_sub_read_local_hist);
		histogram_dump(ns->batch_sub_response_hist);
	}

	if (ns->udf_sub_benchmarks_enabled) {
		histogram_dump(ns->udf_sub_start_hist);
		histogram_dump(ns->udf_sub_restart_hist);
		histogram_dump(ns->udf_sub_dup_res_hist);
		histogram_dump(ns->udf_sub_master_hist);
		histogram_dump(ns->udf_sub_repl_write_hist);
		histogram_dump(ns->udf_sub_response_hist);
	}

	if (ns->storage_benchmarks_enabled) {
		as_storage_ticker_stats(ns);
	}

	as_sindex_histogram_dumpall(ns);
}


void
log_mem_stats(size_t total_ns_memory_inuse)
{
#ifdef MEM_COUNT
	if (g_config.memory_accounting) {
		mem_count_stats();
	}
#endif

#ifdef USE_ASM
	if (g_asm_hook_enabled) {
		static uint64_t iter = 0;
		static asm_stats_t* asm_stats = NULL;
		static vm_stats_t* vm_stats = NULL;
		size_t vm_size = 0;
		size_t total_accounted_memory = 0;

		as_asm_hook((void*)iter++, &asm_stats, &vm_stats);

		if (asm_stats) {
#ifdef DEBUG_ASM
			fprintf(stderr, "***THR_INFO:  asm:  mem_count: %lu ; net_mmaps: %lu ; net_shm: %lu***\n",
					asm_stats->mem_count, asm_stats->net_mmaps, asm_stats->net_shm);
#endif
			total_accounted_memory = asm_stats->mem_count + asm_stats->net_mmaps + asm_stats->net_shm;
		}

		if (vm_stats) {
			// N.B.: The VM stats description is used implicitly by the accessor
			// "vm_stats_*()" macros!
			vm_stats_desc_t* vm_stats_desc = vm_stats->desc;
			vm_size = vm_stats_get_key_value(vm_stats, VM_SIZE);
#ifdef DEBUG_ASM
			fprintf(stderr, "***THR_INFO:  vm:  %s: %lu KB; %s: %lu KB ; %s: %lu KB ; %s: %lu KB***\n",
					vm_stats_key_name(VM_PEAK),
					vm_stats_get_key_value(vm_stats, VM_PEAK),
					vm_stats_key_name(VM_SIZE),
					vm_size,
					vm_stats_key_name(VM_RSS),
					vm_stats_get_key_value(vm_stats, VM_RSS),
					vm_stats_key_name(VM_DATA),
					vm_stats_get_key_value(vm_stats, VM_DATA));
#endif

			// Convert from KB to B.
			vm_size *= 1024;

			// Calculate the storage efficiency percentages.
			double dynamic_eff = ((double) total_accounted_memory / (double) MAX(vm_size, 1)) * 100.0;
			double obj_eff = ((double) total_ns_memory_inuse / (double) MAX(vm_size, 1)) * 100.0;

#ifdef DEBUG_ASM
			fprintf(stderr, "VM size: %lu ; Total Accounted Memory: %lu (%.3f%%) ; Total NS Memory in use: %lu (%.3f%%)\n",
					vm_size, total_accounted_memory, dynamic_eff, total_ns_memory_inuse, obj_eff);
#endif
			cf_info(AS_INFO, "VM size: %lu ; Total Accounted Memory: %lu (%.3f%%) ; Total NS Memory in use: %lu (%.3f%%)",
					vm_size, total_accounted_memory, dynamic_eff, total_ns_memory_inuse, obj_eff);
		}
	}
#endif // USE_ASM

	if (g_mstats_enabled) {
		info_log_with_datestamp(malloc_stats);
	}
}
