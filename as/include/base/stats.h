/*
 * stats.h
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

#pragma once

//==========================================================
// Includes.
//

#include <stdint.h>

#include "citrusleaf/cf_atomic.h"

#include "hist.h"


//==========================================================
// Typedefs.
//

typedef struct as_stats_s {

	cf_atomic64		global_record_ref_count; // TODO - can't we get rid of this?

	// Connection stats.
	cf_atomic64		proto_connections_opened; // not just a statistic
	cf_atomic64		proto_connections_closed; // not just a statistic
	// In ticker but not collected via info:
	cf_atomic64		heartbeat_connections_opened;
	cf_atomic64		heartbeat_connections_closed;
	cf_atomic64		fabric_connections_opened;
	cf_atomic64		fabric_connections_closed;

	// Heartbeat stats.
	cf_atomic64		heartbeat_received_self;
	cf_atomic64		heartbeat_received_foreign;

	// Demarshal stats.
	uint64_t		reaper_count; // not in ticker - incremented only in reaper thread

	// Info stats.
	cf_atomic64		info_complete;

	// Proxy stats.
	uint64_t		proxy_retry; // not in ticker - incremented only in proxy retransmit thread

	// Early transaction errors.
	cf_atomic64		n_demarshal_error;
	cf_atomic64		n_tsvc_client_error;
	cf_atomic64		n_tsvc_batch_sub_error;
	cf_atomic64		n_tsvc_udf_sub_error;

	// Batch-index stats.
	cf_atomic64		batch_index_initiate; // not in ticker - not just a statistic
	cf_atomic64		batch_index_complete;
	cf_atomic64		batch_index_errors;
	cf_atomic64		batch_index_timeout;

	// Batch-index stats.
	cf_atomic64		batch_index_huge_buffers; // not in ticker
	cf_atomic64		batch_index_created_buffers; // not in ticker
	cf_atomic64		batch_index_destroyed_buffers; // not in ticker

	// "Old" batch stats.
	cf_atomic64		batch_initiate; // not in ticker
	cf_atomic64		batch_errors; // not in ticker
	cf_atomic64		batch_timeout; // not in ticker

	// Query & secondary index stats.
	cf_atomic64		query_false_positives;
	cf_atomic64		sindex_gc_timedout; // number of times sindex gc iteration timed out waiting for partition lock
	uint64_t		sindex_gc_inactivity_dur; // cumulative sum of sindex gc thread inactivity
	uint64_t		sindex_gc_activity_dur; // cumulative sum of sindex gc thread activity
	uint64_t		sindex_gc_list_creation_time; // cumulative sum of list creation phase in sindex gc
	uint64_t		sindex_gc_list_deletion_time; // cumulative sum of list deletion phase in sindex gc
	uint64_t		sindex_gc_objects_validated; // cumulative sum of sindex objects validated
	uint64_t		sindex_gc_garbage_found; // amount of garbage found during list creation phase
	uint64_t		sindex_gc_garbage_cleaned; // amount of garbage deleted during list deletion phase

	// Fabric stats.
	cf_atomic64		fabric_msgs_sent; // not in ticker
	cf_atomic64		fabric_msgs_rcvd; // not in ticker

	//--------------------------------------------
	// Histograms.
	//

	histogram*		batch_index_hist;
	bool			batch_index_hist_active; // automatically activated

	histogram*		info_hist;

	histogram*		svc_demarshal_hist;
	histogram*		svc_queue_hist;

	histogram*		_sindex_gc_validate_obj_hist; // time taken to validate sindex object
	histogram*		_sindex_gc_delete_obj_hist; // time taken to delete sindex object by gc
	histogram*		_sindex_gc_pimd_rlock_hist; // time spent under pimd rlock by sindex gc - TODO - unused?
	histogram*		_sindex_gc_pimd_wlock_hist; // time spent under pimd wlock by sindex gc - TODO - unused?

	histogram*		ldt_multiop_prole_hist; // tracks LDT multi op replication performance (in fabric)
	histogram*		ldt_update_record_cnt_hist; // tracks number of records written (write/update) by LDT UDF excluding parent record
	histogram*		ldt_io_record_cnt_hist; // tracks number of records opened (write/update) by LDT UDF excluding parent record
	histogram*		ldt_update_io_bytes_hist; // tracks number bytes written by LDT every transaction - TODO - unused?
	histogram*		ldt_hist; // tracks ldt performance

} as_stats;


//==========================================================
// Public API.
//

// For now this is in thr_info.c, until a separate .c file is worth it.
void as_stats_init();
extern as_stats g_stats;
