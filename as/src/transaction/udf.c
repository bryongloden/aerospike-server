/*
 * udf.c
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

#include "transaction/udf.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "aerospike/as_aerospike.h"
#include "aerospike/as_buffer.h"
#include "aerospike/as_log.h"
#include "aerospike/as_module.h"
#include "aerospike/as_msgpack.h"
#include "aerospike/as_serializer.h"
#include "aerospike/as_types.h"
#include "aerospike/as_udf_context.h"
#include "aerospike/mod_lua.h"

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"

#include "dynbuf.h"
#include "fault.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/ldt.h"
#include "base/ldt_aerospike.h"
#include "base/proto.h"
#include "base/secondary_index.h"
#include "base/transaction.h"
#include "base/transaction_policy.h"
#include "base/udf_aerospike.h"
#include "base/udf_arglist.h"
#include "base/udf_cask.h"
#include "base/udf_record.h"
#include "base/udf_timer.h"
#include "transaction/duplicate_resolve.h"
#include "transaction/proxy.h"
#include "transaction/replica_write.h"
#include "transaction/rw_request.h"
#include "transaction/rw_request_hash.h"
#include "transaction/rw_utils.h"


//==========================================================
// Typedefs & constants.
//

static const cf_fault_severity as_log_level_map[5] = {
	[AS_LOG_LEVEL_ERROR] = CF_WARNING,
	[AS_LOG_LEVEL_WARN]	= CF_WARNING,
	[AS_LOG_LEVEL_INFO]	= CF_INFO,
	[AS_LOG_LEVEL_DEBUG] = CF_DEBUG,
	[AS_LOG_LEVEL_TRACE] = CF_DETAIL
};

typedef struct udf_call_s {
	udf_def*		def;
	as_transaction* tr;
} udf_call;

typedef struct pickle_info_s {
	uint8_t*	rec_props_data;
	uint32_t	rec_props_size;
	uint8_t*	buf;
	size_t		buf_size;
} pickle_info;


//==========================================================
// Forward Declarations.
//

bool log_callback(as_log_level level, const char* func, const char* file,
		uint32_t line, const char* fmt, ...);

bool start_udf_dup_res(rw_request* rw, as_transaction* tr);
bool start_udf_repl_write(rw_request* rw, as_transaction* tr);
bool udf_dup_res_cb(rw_request* rw);
bool udf_repl_write_after_dup_res(rw_request* rw, as_transaction* tr);
void udf_repl_write_cb(rw_request* rw);

void send_udf_response(as_transaction* tr, cf_dyn_buf* db);
void udf_timeout_cb(rw_request* rw);

transaction_status udf_master(rw_request* rw, as_transaction* tr);
udf_optype udf_master_apply(udf_call* call, rw_request* rw);
int udf_apply_record(udf_call* call, as_rec* rec, as_result* result);
uint64_t udf_end_time(time_tracker* tt);
int udf_finish(ldt_record* lrecord, rw_request* rw, udf_optype* lrecord_op,
		uint16_t set_id);
udf_optype udf_getop(udf_record* urecord);
void udf_post_processing(udf_record* urecord, udf_optype* urecord_op,
		uint16_t set_id);
void write_udf_post_processing(as_transaction* tr, as_storage_rd* rd,
		uint8_t** pickled_buf, size_t* pickled_sz,
		as_rec_props* p_pickled_rec_props);
bool udf_pickle_all(as_storage_rd* rd, pickle_info* pickle);

void update_ldt_stats(as_namespace* ns, udf_optype op, int ret,
		bool is_success);
void update_lua_complete_stats(uint8_t origin, as_namespace* ns, udf_optype op,
		int ret, bool is_success);

void process_failure_str(udf_call* call, const char* err_str, size_t len,
		cf_dyn_buf* db);
void process_result(const as_result* result, udf_call* call, cf_dyn_buf* db);
void process_udf_failure(udf_call* call, const as_string* s, cf_dyn_buf* db);
void process_response(udf_call* call, const char* bin_name, const as_val* val,
		cf_dyn_buf* db);

static inline void
client_udf_update_stats(as_namespace* ns, uint8_t result_code)
{
	switch (result_code) {
	case AS_PROTO_RESULT_OK:
		cf_atomic64_incr(&ns->n_client_udf_complete);
		break;
	case AS_PROTO_RESULT_FAIL_TIMEOUT:
		cf_atomic64_incr(&ns->n_client_udf_timeout);
		break;
	default:
		cf_atomic64_incr(&ns->n_client_udf_error);
		break;
	}
}

static inline void
udf_sub_udf_update_stats(as_namespace* ns, uint8_t result_code)
{
	switch (result_code) {
	case AS_PROTO_RESULT_OK:
		cf_atomic64_incr(&ns->n_udf_sub_udf_complete);
		break;
	case AS_PROTO_RESULT_FAIL_TIMEOUT:
		cf_atomic64_incr(&ns->n_udf_sub_udf_timeout);
		break;
	default:
		cf_atomic64_incr(&ns->n_udf_sub_udf_error);
		break;
	}
}

static inline bool
udf_zero_bins_left(udf_record* urecord)
{
	return (urecord->flag & UDF_RECORD_FLAG_IS_SUBRECORD) == 0 &&
			(urecord->flag & UDF_RECORD_FLAG_OPEN) != 0 &&
			! as_bin_inuse_has(urecord->rd);
}

static inline void
process_failure(udf_call* call, const as_val* val, cf_dyn_buf* db)
{
	process_response(call, "FAILURE", val, db);
}

static inline void
process_success(udf_call* call, const as_val* val, cf_dyn_buf* db)
{
	process_response(call, "SUCCESS", val, db);
}


//==========================================================
// Globals.
//

as_aerospike g_as_aerospike;


//==========================================================
// Public API.
//

void
as_udf_init()
{
	as_module_configure(&mod_lua, &g_config.mod_lua);
	as_log_set_callback(log_callback);
	udf_cask_init();
	as_aerospike_init(&g_as_aerospike, NULL, &udf_aerospike_hooks);
	ldt_init();
}


// Public API for udf_def class, not big enough for it's own file.
udf_def*
udf_def_init_from_msg(udf_def* def, const as_transaction* tr)
{
	as_msg* m = &tr->msgp->msg;
	as_msg_field* filename =
			as_msg_field_get(m, AS_MSG_FIELD_TYPE_UDF_FILENAME);

	if (! filename) {
		return NULL;
	}

	as_msg_field* function =
			as_msg_field_get(m, AS_MSG_FIELD_TYPE_UDF_FUNCTION);

	if (! function) {
		return NULL;
	}

	as_msg_field* arglist = as_msg_field_get(m, AS_MSG_FIELD_TYPE_UDF_ARGLIST);

	if (! arglist) {
		return NULL;
	}

	as_msg_field_get_strncpy(filename, def->filename, sizeof(def->filename));
	as_msg_field_get_strncpy(function, def->function, sizeof(def->function));
	def->arglist = arglist;

	as_msg_field* op = as_transaction_has_udf_op(tr) ?
			as_msg_field_get(m, AS_MSG_FIELD_TYPE_UDF_OP) : NULL;

	def->type = op ? *op->data : AS_UDF_OP_KVS;

	return def;
}


transaction_status
as_udf_start(as_transaction* tr)
{
	BENCHMARK_START(tr, udf, FROM_CLIENT);
	BENCHMARK_START(tr, udf_sub, FROM_IUDF);

	// Apply XDR filter.
	if (! xdr_allows_write(tr)) {
		tr->result_code = AS_PROTO_RESULT_FAIL_FORBIDDEN;
		send_udf_response(tr, NULL);
		return TRANS_DONE_ERROR;
	}

	// Don't know if UDF is read or delete - check that we aren't backed up.
	if (as_storage_overloaded(tr->rsv.ns)) {
		tr->result_code = AS_PROTO_RESULT_FAIL_DEVICE_OVERLOAD;
		send_udf_response(tr, NULL);
		return TRANS_DONE_ERROR;
	}

	// Create rw_request and add to hash.
	rw_request_hkey hkey = { tr->rsv.ns->id, tr->keyd };
	rw_request* rw = rw_request_create(&tr->keyd);
	transaction_status status = rw_request_hash_insert(&hkey, rw, tr);

	// If rw_request wasn't inserted in hash, transaction is finished.
	if (status != TRANS_IN_PROGRESS) {
		rw_request_release(rw);

		if (status != TRANS_WAITING) {
			send_udf_response(tr, NULL);
		}

		return status;
	}
	// else - rw_request is now in hash, continue...

	if (g_config.write_duplicate_resolution_disable) {
		// Note - preventing duplicate resolution this way allows
		// rw_request_destroy() to handle dup_msg[] cleanup correctly.
		tr->rsv.n_dupl = 0;
	}

	// If there are duplicates to resolve, start doing so.
	if (tr->rsv.n_dupl != 0) {
		if (! start_udf_dup_res(rw, tr)) {
			rw_request_hash_delete(&hkey, rw);
			tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
			send_udf_response(tr, NULL);
			return TRANS_DONE_ERROR;
		}

		// Started duplicate resolution.
		return TRANS_IN_PROGRESS;
	}
	// else - no duplicate resolution phase, apply operation to master.

	status = udf_master(rw, tr);

	BENCHMARK_NEXT_DATA_POINT(tr, udf, master);
	BENCHMARK_NEXT_DATA_POINT(tr, udf_sub, master);

	// If error or UDF was a read, transaction is finished.
	if (status != TRANS_IN_PROGRESS) {
		send_udf_response(tr, &rw->response_db);
		rw_request_hash_delete(&hkey, rw);
		return status;
	}

	// Set up the nodes to which we'll write replicas.
	rw->n_dest_nodes = as_partition_getreplica_readall(tr->rsv.ns, tr->rsv.pid,
			rw->dest_nodes);

	// If we don't need replica writes, transaction is finished.
	// TODO - consider a single-node fast path bypassing hash and pickling?
	if (rw->n_dest_nodes == 0) {
		send_udf_response(tr, &rw->response_db);
		rw_request_hash_delete(&hkey, rw);
		return TRANS_DONE_SUCCESS;
	}

	if (! start_udf_repl_write(rw, tr)) {
		rw_request_hash_delete(&hkey, rw);
		tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
		send_udf_response(tr, NULL);
		return TRANS_DONE_ERROR;
	}

	// Started replica write.
	return TRANS_IN_PROGRESS;
}


//==========================================================
// Local helpers - initialization.
//

bool
log_callback(as_log_level level, const char* func, const char* file,
		uint32_t line, const char* fmt, ...)
{
	cf_fault_severity severity = as_log_level_map[level];

	if (severity > cf_fault_filter[AS_UDF]) {
		return true;
	}

	va_list ap;

	va_start(ap, fmt);
	char message[1024] = { '\0' };
	vsnprintf(message, 1024, fmt, ap);
	va_end(ap);

	cf_fault_event(AS_UDF, severity, file, line, "%s", message);

	return true;
}


//==========================================================
// Local helpers - transaction flow.
//

bool
start_udf_dup_res(rw_request* rw, as_transaction* tr)
{
	// Finish initializing rw, construct and send dup-res message.

	if (! dup_res_make_message(rw, tr, true)) {
		return false;
	}

	rw->respond_client_on_master_completion = respond_on_master_complete(tr);

	pthread_mutex_lock(&rw->lock);

	dup_res_setup_rw(rw, tr, udf_dup_res_cb, udf_timeout_cb);
	send_rw_messages(rw);

	pthread_mutex_unlock(&rw->lock);

	return true;
}


bool
start_udf_repl_write(rw_request* rw, as_transaction* tr)
{
	// Finish initializing rw, construct and send repl-write message.

	if (! repl_write_make_message(rw, tr)) { // TODO - split this?
		return false;
	}

	rw->respond_client_on_master_completion = respond_on_master_complete(tr);

	if (rw->respond_client_on_master_completion) {
		// Don't wait for replication. When replication is complete, we won't
		// call send_udf_response() again.
		send_udf_response(tr, &rw->response_db);
	}

	pthread_mutex_lock(&rw->lock);

	repl_write_setup_rw(rw, tr, udf_repl_write_cb, udf_timeout_cb);
	send_rw_messages(rw);

	pthread_mutex_unlock(&rw->lock);

	return true;
}


bool
udf_dup_res_cb(rw_request* rw)
{
	BENCHMARK_NEXT_DATA_POINT(rw, udf, dup_res);
	BENCHMARK_NEXT_DATA_POINT(rw, udf_sub, dup_res);

	as_transaction tr;
	as_transaction_init_from_rw(&tr, rw);

	transaction_status status = udf_master(rw, &tr);

	BENCHMARK_NEXT_DATA_POINT((&tr), udf, master);
	BENCHMARK_NEXT_DATA_POINT((&tr), udf_sub, master);

	if (status != TRANS_IN_PROGRESS) {
		send_udf_response(&tr, &rw->response_db);
		return true;
	}

	// Set up the nodes to which we'll write replicas.
	rw->n_dest_nodes = as_partition_getreplica_readall(tr.rsv.ns, tr.rsv.pid,
			rw->dest_nodes);

	// If we don't need replica writes, transaction is finished.
	if (rw->n_dest_nodes == 0) {
		send_udf_response(&tr, &rw->response_db);
		return true;
	}

	if (! udf_repl_write_after_dup_res(rw, &tr)) {
		tr.result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
		send_udf_response(&tr, NULL);
		return true;
	}

	// Started replica write - don't delete rw_request from hash.
	return false;
}


bool
udf_repl_write_after_dup_res(rw_request* rw, as_transaction* tr)
{
	// Recycle rw_request that was just used for duplicate resolution to now do
	// replica writes. Note - we are under the rw_request lock here!

	if (! repl_write_make_message(rw, tr)) { // TODO - split this?
		return false;
	}

	if (rw->respond_client_on_master_completion) {
		// Don't wait for replication. When replication is complete, we won't
		// call send_udf_response() again.
		send_udf_response(tr, &rw->response_db);
	}

	repl_write_reset_rw(rw, tr, udf_repl_write_cb);
	send_rw_messages(rw);

	return true;
}


void
udf_repl_write_cb(rw_request* rw)
{
	BENCHMARK_NEXT_DATA_POINT(rw, udf, repl_write);
	BENCHMARK_NEXT_DATA_POINT(rw, udf_sub, repl_write);

	as_transaction tr;
	as_transaction_init_from_rw(&tr, rw);

	send_udf_response(&tr, &rw->response_db);

	// Finished transaction - rw_request cleans up reservation and msgp!
}


//==========================================================
// Local helpers - transaction end.
//

void
send_udf_response(as_transaction* tr, cf_dyn_buf* db)
{
	// Paranoia - shouldn't get here on losing race with timeout.
	if (! tr->from.any) {
		cf_warning(AS_RW, "transaction origin %u has null 'from'", tr->origin);
		return;
	}

	// Note - if tr was setup from rw, rw->from.any has been set null and
	// informs timeout it lost the race.

	switch (tr->origin) {
	case FROM_CLIENT:
		if (db && db->used_sz != 0) {
			as_msg_send_ops_reply(tr->from.proto_fd_h, db);
		}
		else {
			as_msg_send_reply(tr->from.proto_fd_h, tr->result_code,
					tr->generation, tr->void_time, NULL, NULL, 0, NULL,
					as_transaction_trid(tr), NULL);
		}
		BENCHMARK_NEXT_DATA_POINT(tr, udf, response);
		HIST_TRACK_ACTIVATE_INSERT_DATA_POINT(tr, udf_hist);
		client_udf_update_stats(tr->rsv.ns, tr->result_code);
		break;
	case FROM_PROXY:
		if (db && db->used_sz != 0) {
			as_proxy_send_ops_response(tr->from.proxy_node,
					tr->from_data.proxy_tid, db);
		}
		else {
			as_proxy_send_response(tr->from.proxy_node, tr->from_data.proxy_tid,
					tr->result_code, tr->generation, tr->void_time, NULL, NULL,
					0, NULL, as_transaction_trid(tr), NULL);
		}
		break;
	case FROM_IUDF:
		if (db && db->used_sz != 0) {
			cf_crash(AS_RW, "unexpected - internal udf has response");
		}
		tr->from.iudf_orig->cb(tr->from.iudf_orig->udata, tr->result_code);
		BENCHMARK_NEXT_DATA_POINT(tr, udf_sub, response);
		udf_sub_udf_update_stats(tr->rsv.ns, tr->result_code);
		break;
	case FROM_BATCH:
	case FROM_NSUP:
		// Should be impossible for batch reads and nsup deletes to get here.
	default:
		cf_crash(AS_RW, "unexpected transaction origin %u", tr->origin);
		break;
	}

	tr->from.any = NULL; // needed only for respond-on-master-complete
}


void
udf_timeout_cb(rw_request* rw)
{
	if (! rw->from.any) {
		return; // lost race against dup-res or repl-write callback
	}

	switch (rw->origin) {
	case FROM_CLIENT:
		as_end_of_transaction_force_close(rw->from.proto_fd_h);
		// Timeouts aren't included in histograms.
		client_udf_update_stats(rw->rsv.ns, AS_PROTO_RESULT_FAIL_TIMEOUT);
		break;
	case FROM_PROXY:
		break;
	case FROM_IUDF:
		rw->from.iudf_orig->cb(rw->from.iudf_orig->udata,
				AS_PROTO_RESULT_FAIL_TIMEOUT);
		// Timeouts aren't included in histograms.
		udf_sub_udf_update_stats(rw->rsv.ns, AS_PROTO_RESULT_FAIL_TIMEOUT);
		break;
	case FROM_BATCH:
	case FROM_NSUP:
		// Should be impossible for batch reads and nsup deletes to get here.
	default:
		cf_crash(AS_RW, "unexpected transaction origin %u", rw->origin);
		break;
	}

	rw->from.any = NULL; // inform other callback it lost the race
}


//==========================================================
// Local helpers - UDF.
//

transaction_status
udf_master(rw_request* rw, as_transaction* tr)
{
	rw->has_udf = true;

	udf_def def;
	udf_call call = { &def, tr };

	if (tr->origin == FROM_IUDF) {
		call.def = &tr->from.iudf_orig->def;
	}
	else if (! udf_def_init_from_msg(call.def, tr)) {
		cf_warning(AS_UDF, "failed udf_def_init_from_msg");
		tr->result_code = AS_PROTO_RESULT_FAIL_PARAMETER;
		return TRANS_DONE_ERROR;
	}

	udf_optype optype = udf_master_apply(&call, rw);

	if (UDF_OP_IS_READ(optype) || optype == UDF_OPTYPE_NONE) {
		// UDF is done, no replica writes needed.
		return TRANS_DONE_SUCCESS;
	}

	if (UDF_OP_IS_LDT(optype)) {
		rw->is_multiop = true;
	}

	// UDFs send original msg for replica deletes.
	// Note - not currently necessary to set this message flag.
	if (UDF_OP_IS_DELETE(optype)) {
		tr->msgp->msg.info2 |= AS_MSG_INFO2_DELETE;
	}

	return TRANS_IN_PROGRESS;
}


udf_optype
udf_master_apply(udf_call* call, rw_request* rw)
{
	as_transaction* tr = call->tr;
	as_namespace* ns = tr->rsv.ns;

	// Prepare UDF record.

	as_index_ref r_ref;
	r_ref.skip_lock = false;

	as_storage_rd rd;

	udf_record urecord;
	udf_record_init(&urecord, true);

	xdr_dirty_bins dirty_bins;
	xdr_clear_dirty_bins(&dirty_bins);

	urecord.r_ref	= &r_ref;
	urecord.tr		= tr;
	urecord.rd		= &rd;
	urecord.dirty	= &dirty_bins;
	urecord.keyd	= tr->keyd;

	// Prepare LDT record.

	ldt_record lrecord;
	ldt_record_init(&lrecord);

	as_rec urec;
	as_rec_init(&urec, &urecord, &udf_record_hooks);

	// Link lrecord and urecord.
	lrecord.h_urec	= &urec;
	urecord.lrecord	= &lrecord;

	// Find record in index.

	int get_rv = as_record_get(tr->rsv.tree, &tr->keyd, &r_ref, ns);

	if (get_rv == 0 && as_record_is_expired(r_ref.r)) {
		// If record is expired, pretend it was not found.
		as_record_done(&r_ref, ns);
		get_rv = -1;
	}

	if (get_rv == -1 && tr->origin == FROM_IUDF) {
		// Internal UDFs must not create records.
		tr->result_code = AS_PROTO_RESULT_FAIL_NOTFOUND;
		process_failure(call, NULL, &rw->response_db);
		ldt_record_destroy(&lrecord);
		return UDF_OPTYPE_NONE;
	}

	// Needed for XDR shipping.
	uint32_t set_id = INVALID_SET_ID;

	// Open storage record.

	if (get_rv == 0) {
		urecord.flag |= (UDF_RECORD_FLAG_OPEN | UDF_RECORD_FLAG_PREEXISTS);

		if (udf_storage_record_open(&urecord) != 0) {
			udf_record_close(&urecord);
			tr->result_code = AS_PROTO_RESULT_FAIL_BIN_NAME; // overloaded... add bin_count error?
			process_failure(call, NULL, &rw->response_db);
			ldt_record_destroy(&lrecord);
			return UDF_OPTYPE_NONE;
		}

		as_msg* m = &tr->msgp->msg;

		// If both the record and the message have keys, check them.
		if (rd.key) {
			if (as_transaction_has_key(tr) && ! check_msg_key(m, &rd)) {
				udf_record_close(&urecord);
				tr->result_code = AS_PROTO_RESULT_FAIL_KEY_MISMATCH;
				process_failure(call, NULL, &rw->response_db);
				ldt_record_destroy(&lrecord);
				return UDF_OPTYPE_NONE;
			}
		}
		else {
			// If the message has a key, apply it to the record.
			if (! get_msg_key(tr, &rd)) {
				udf_record_close(&urecord);
				tr->result_code = AS_PROTO_RESULT_FAIL_UNSUPPORTED_FEATURE;
				process_failure(call, NULL, &rw->response_db);
				ldt_record_destroy(&lrecord);
				return UDF_OPTYPE_NONE;
			}

			urecord.flag |= UDF_RECORD_FLAG_METADATA_UPDATED;
		}

		if (as_ldt_parent_storage_get_version(&rd, &lrecord.version, false,
				__FILE__, __LINE__)) {
			lrecord.version = as_ldt_generate_version();
		}

		// Save the set-ID for XDR in case record is deleted.
		set_id = as_index_get_set_id(urecord.r_ref->r);
	}
	else {
		urecord.flag &= ~(UDF_RECORD_FLAG_OPEN |
				UDF_RECORD_FLAG_STORAGE_OPEN |
				UDF_RECORD_FLAG_PREEXISTS);
	}

	// Run UDF.

	// This as_rec needs to be in the heap - once passed into the lua scope it
	// gets garbage collected later. Also, the destroy hook is set to NULL so
	// garbage collection has nothing to do. For ldt_record, clean up and post-
	// processing has to be in process context under transactional protection.
	as_rec* lrec = as_rec_new(&lrecord, &ldt_record_hooks);
	as_val_reserve(lrec);

	as_result result;
	as_result_init(&result);

	udf_optype optype = UDF_OPTYPE_NONE;

	int apply_rv = udf_apply_record(call, lrec, &result);

	if (apply_rv == 0) {
		if ((lrecord.udf_context & UDF_CONTEXT_LDT) != 0) {
			histogram_insert_raw(g_stats.ldt_io_record_cnt_hist,
					lrecord.subrec_io + 1);
		}

		if (udf_finish(&lrecord, rw, &optype, set_id) != 0) {
			cf_warning(AS_UDF, "failed udf_finish");
			// ... and ???
		}

		if (! result.is_success) {
			ldt_update_err_stats(ns, result.value);
		}

		process_result(&result, call, &rw->response_db);
	}
	else {
		udf_record_close(&urecord);

		char* rs = as_module_err_string(apply_rv);

		tr->result_code = AS_PROTO_RESULT_FAIL_UDF_EXECUTION;
		process_failure_str(call, rs, strlen(rs), &rw->response_db);
		cf_free(rs);
	}

	if ((lrecord.udf_context & UDF_CONTEXT_LDT) != 0) {
		update_ldt_stats(ns, optype, apply_rv, result.is_success);
	}
	else {
		update_lua_complete_stats(tr->origin, ns, optype, apply_rv,
				result.is_success);
	}

	as_result_destroy(&result);
	as_rec_destroy(lrec);
	ldt_record_destroy(&lrecord);

	return optype;
}


int
udf_apply_record(udf_call* call, as_rec* rec, as_result* result)
{
	as_list arglist;
	as_list_init(&arglist, call->def->arglist, &udf_arglist_hooks);

	time_tracker udf_timer_tracker = {
		.udata		= as_rec_source(rec),
		.end_time	= udf_end_time
	};

	udf_timer_setup(&udf_timer_tracker);

	as_timer timer;
	as_timer_init(&timer, &udf_timer_tracker, &udf_timer_hooks);

	as_udf_context ctx = {
		.as			= &g_ldt_aerospike,
		.timer		= &timer,
		.memtracker	= NULL
	};

	uint64_t start_time = g_config.ldt_benchmarks ? cf_getns() : 0;

	int apply_rv = as_module_apply_record(&mod_lua, &ctx, call->def->filename,
			call->def->function, rec, &arglist, result);

	if (start_time != 0) {
		ldt_record* lrecord = (ldt_record*)as_rec_source(rec);

		if ((lrecord->udf_context & UDF_CONTEXT_LDT) != 0) {
			histogram_insert_data_point(g_stats.ldt_hist, start_time);
		}
	}

	udf_timer_cleanup();
	as_list_destroy(&arglist);

	return apply_rv;
}


uint64_t
udf_end_time(time_tracker* tt)
{
	ldt_record* lrecord = (ldt_record*)tt->udata;

	if (! lrecord) {
		return -1; // TODO - should be impossible.
	}

	udf_record* urecord = (udf_record*)as_rec_source(lrecord->h_urec);

	if (! urecord) {
		return -1; // TODO - should be impossible.
	}

	return urecord->tr->end_time;
}


int
udf_finish(ldt_record* lrecord, rw_request* rw, udf_optype* lrecord_op,
		uint16_t set_id)
{
	*lrecord_op = UDF_OPTYPE_READ;

	int ret = 0;
	bool is_ldt = false;
	int subrec_count = 0;

	udf_record* h_urecord = as_rec_source(lrecord->h_urec);
	udf_optype h_urecord_op = udf_getop(h_urecord);

	if (h_urecord_op == UDF_OPTYPE_DELETE) {
		udf_post_processing(h_urecord, &h_urecord_op, set_id);

		rw->pickled_buf = NULL;
		rw->pickled_sz = 0;
		as_rec_props_clear(&rw->pickled_rec_props);
		*lrecord_op = UDF_OPTYPE_DELETE;
	}
	else {
		if (h_urecord_op == UDF_OPTYPE_WRITE) {
			*lrecord_op = UDF_OPTYPE_WRITE;
		}

		FOR_EACH_SUBRECORD(i, j, lrecord) {
			udf_record* c_urecord = &lrecord->chunk[i].slots[j].c_urecord;
			udf_optype c_urecord_op = udf_getop(c_urecord);

			if (UDF_OP_IS_WRITE(c_urecord_op)) {
				is_ldt = true;
				subrec_count++;
			}

			udf_post_processing(c_urecord, &c_urecord_op, set_id);
		}

		// Process the parent record last .. this is to make sure the lock is
		// held until the end.
		udf_post_processing(h_urecord, &h_urecord_op, set_id);

		if (is_ldt) {
			// Create the multiop pickled buf.
			ret = as_ldt_record_pickle(lrecord, &rw->pickled_buf,
					&rw->pickled_sz);

			FOR_EACH_SUBRECORD(i, j, lrecord) {
				udf_record* c_urecord = &lrecord->chunk[i].slots[j].c_urecord;
				// Cleanup in case pickle code bailed out, either:
				// - single node, no replica
				// - failed to pack stuff up
				udf_record_cleanup(c_urecord, true);
			}
		}
		else {
			// Normal UDF case - pass on pickled buf created for the record.
			rw->pickled_buf			= h_urecord->pickled_buf;
			rw->pickled_sz			= h_urecord->pickled_sz;
			rw->pickled_rec_props	= h_urecord->pickled_rec_props;

			udf_record_cleanup(h_urecord, false);
		}
	}

	udf_record_cleanup(h_urecord, true);

	if (UDF_OP_IS_WRITE(*lrecord_op) &&
			(lrecord->udf_context & UDF_CONTEXT_LDT) != 0) {
		histogram_insert_raw(g_stats.ldt_update_record_cnt_hist,
				subrec_count + 1);
	}

	if (is_ldt) {
		if (UDF_OP_IS_WRITE(*lrecord_op)) {
			*lrecord_op = UDF_OPTYPE_LDT_WRITE;
		}
		else if (UDF_OP_IS_DELETE(*lrecord_op)) {
			*lrecord_op = UDF_OPTYPE_LDT_DELETE;
		}
		else if (UDF_OP_IS_READ(*lrecord_op)) {
			*lrecord_op = UDF_OPTYPE_LDT_READ;
		}
	}

	return ret;
}


udf_optype
udf_getop(udf_record* urecord)
{
	udf_optype optype;

	if ((urecord->flag & UDF_RECORD_FLAG_HAS_UPDATES) != 0) {
		if ((urecord->flag & UDF_RECORD_FLAG_OPEN) != 0) {
			optype = UDF_OPTYPE_WRITE;
		}
		else {
			// If the record has updates and it is not open, and if it pre-
			// existed, it's an update followed by a delete.
			if ((urecord->flag & UDF_RECORD_FLAG_PREEXISTS) != 0) {
				optype = UDF_OPTYPE_DELETE;
			}
			// If the record did not pre-exist and has updates and it is not
			// open, then it is create followed by delete - essentially a no-op.
			else {
				optype = UDF_OPTYPE_NONE;
			}
		}
	}
	else if ((urecord->flag & UDF_RECORD_FLAG_PREEXISTS) != 0 &&
			(urecord->flag & UDF_RECORD_FLAG_OPEN) == 0) {
		optype = UDF_OPTYPE_DELETE;
	}
	else {
		optype = UDF_OPTYPE_READ;
	}

	if (udf_zero_bins_left(urecord)) {
		optype = UDF_OPTYPE_DELETE;
	}

	return optype;
}


void
udf_post_processing(udf_record* urecord, udf_optype* urecord_op,
		uint16_t set_id)
{
	as_storage_rd* rd	= urecord->rd;
	as_transaction* tr	= urecord->tr;
	as_index_ref* r_ref	= urecord->r_ref;

	urecord->pickled_buf = NULL;
	urecord->pickled_sz = 0;
	as_rec_props_clear(&urecord->pickled_rec_props);
	bool udf_xdr_ship_op = false;

	*urecord_op = udf_getop(urecord);

	if (UDF_OP_IS_DELETE(*urecord_op) || UDF_OP_IS_WRITE(*urecord_op)) {
		udf_xdr_ship_op = true;
	}

	if (udf_zero_bins_left(urecord)) {
		// Note - record delete via aerospike:remove() does not get here.
		// Not applicable to sub-records unless requested by UDF - orphaned sub-
		// records are eventually overwritten by defrag.
		as_index_delete(tr->rsv.tree, &tr->keyd);
		*urecord_op = UDF_OPTYPE_DELETE;
		as_storage_record_adjust_mem_stats(rd, urecord->starting_memory_bytes);
		cf_atomic64_incr(&tr->rsv.ns->n_deleted_last_bin);
	}
	else if (*urecord_op == UDF_OPTYPE_WRITE) {
		size_t rec_props_data_size = as_storage_record_rec_props_size(rd);
		uint8_t rec_props_data[rec_props_data_size];

		if (rec_props_data_size > 0) {
			as_storage_record_set_rec_props(rd, rec_props_data);
		}

		write_udf_post_processing(tr, rd, &urecord->pickled_buf,
			&urecord->pickled_sz, &urecord->pickled_rec_props);

		// Now ok to accommodate a new stored key...
		if (! as_index_is_flag_set(r_ref->r, AS_INDEX_FLAG_KEY_STORED) &&
				rd->key) {
			if (rd->ns->storage_data_in_memory) {
				as_record_allocate_key(r_ref->r, rd->key, rd->key_size);
			}

			as_index_set_flags(r_ref->r, AS_INDEX_FLAG_KEY_STORED);
		}
		// ... or drop a stored key.
		else if (as_index_is_flag_set(r_ref->r, AS_INDEX_FLAG_KEY_STORED) &&
				! rd->key) {
			if (rd->ns->storage_data_in_memory) {
				as_record_remove_key(r_ref->r);
			}

			as_index_clear_flags(r_ref->r, AS_INDEX_FLAG_KEY_STORED);
		}

		as_storage_record_adjust_mem_stats(rd, urecord->starting_memory_bytes);
	}

	// Collect information for XDR before closing the record.

	as_generation generation = 0;

	if ((urecord->flag & UDF_RECORD_FLAG_OPEN) != 0) {
		generation = r_ref->r->generation;
		set_id = as_index_get_set_id(r_ref->r);
	}

	urecord->op = *urecord_op;

	xdr_dirty_bins dirty_bins;
	xdr_clear_dirty_bins(&dirty_bins);

	if (urecord->dirty && udf_xdr_ship_op && UDF_OP_IS_WRITE(*urecord_op)) {
		xdr_copy_dirty_bins(urecord->dirty, &dirty_bins);
	}

	// Close the record for all the cases.
	udf_record_close(urecord);

	// Write to XDR pipe.
	if (udf_xdr_ship_op) {
		if (UDF_OP_IS_WRITE(*urecord_op)) {
			xdr_write(tr->rsv.ns, tr->keyd, generation, 0, false, set_id,
					&dirty_bins);
		}
		else if (UDF_OP_IS_DELETE(*urecord_op)) {
			xdr_write(tr->rsv.ns, tr->keyd, generation, 0, true, set_id, NULL);
		}
	}
}


void
write_udf_post_processing(as_transaction* tr, as_storage_rd* rd,
		uint8_t** pickled_buf, size_t* pickled_sz,
		as_rec_props* p_pickled_rec_props)
{
	update_metadata_in_index(tr, true, rd->r);

	pickle_info pickle;

	udf_pickle_all(rd, &pickle);

	*pickled_buf = pickle.buf;
	*pickled_sz = pickle.buf_size;
	p_pickled_rec_props->p_data = pickle.rec_props_data;
	p_pickled_rec_props->size = pickle.rec_props_size;

	tr->generation = rd->r->generation;
	tr->void_time = rd->r->void_time;
	tr->last_update_time = rd->r->last_update_time;
}


bool
udf_pickle_all(as_storage_rd* rd, pickle_info* pickle)
{
	if (as_record_pickle(rd->r, rd, &pickle->buf, &pickle->buf_size) != 0) {
		return false;
	}

	pickle->rec_props_data = NULL;
	pickle->rec_props_size = 0;

	// TODO - we could avoid this copy (and maybe even not do this here at all)
	// if all callers malloced rdp->rec_props.p_data upstream for hand-off...
	if (rd->rec_props.p_data) {
		pickle->rec_props_size = rd->rec_props.size;
		pickle->rec_props_data = cf_malloc(pickle->rec_props_size);

		if (! pickle->rec_props_data) {
			cf_free(pickle->buf);
			return false;
		}

		memcpy(pickle->rec_props_data, rd->rec_props.p_data,
				pickle->rec_props_size);
	}

	return true;
}


//==========================================================
// Local helpers - statistics.
//

void
update_ldt_stats(as_namespace* ns, udf_optype op, int ret, bool is_success)
{
	if (UDF_OP_IS_READ(op)) {
		cf_atomic_int_incr(&ns->lstats.ldt_read_reqs);
	}
	else if (UDF_OP_IS_DELETE(op)) {
		cf_atomic_int_incr(&ns->lstats.ldt_delete_reqs);
	}
	else if (UDF_OP_IS_WRITE (op)) {
		cf_atomic_int_incr(&ns->lstats.ldt_write_reqs);
	}

	if (ret == 0) {
		if (is_success) {
			if (UDF_OP_IS_READ(op)) {
				cf_atomic_int_incr(&ns->lstats.ldt_read_success);
			}
			else if (UDF_OP_IS_DELETE(op)) {
				cf_atomic_int_incr(&ns->lstats.ldt_delete_success);
			}
			else if (UDF_OP_IS_WRITE (op)) {
				cf_atomic_int_incr(&ns->lstats.ldt_write_success);
			}
		}
		else {
			cf_atomic_int_incr(&ns->lstats.ldt_errs);
		}
	}
	else {
		cf_atomic_int_incr(&ns->lstats.ldt_errs);
	}
}


void
update_lua_complete_stats(uint8_t origin, as_namespace* ns, udf_optype op,
		int ret, bool is_success)
{
	switch (origin) {
	case FROM_CLIENT:
		if (ret == 0 && is_success) {
			if (UDF_OP_IS_READ(op)) {
				cf_atomic_int_incr(&ns->n_client_lang_read_success);
			}
			else if (UDF_OP_IS_DELETE(op)) {
				cf_atomic_int_incr(&ns->n_client_lang_delete_success);
			}
			else if (UDF_OP_IS_WRITE (op)) {
				cf_atomic_int_incr(&ns->n_client_lang_write_success);
			}
		}
		else {
			cf_info(AS_UDF, "lua error, ret:%d", ret);
			cf_atomic_int_incr(&ns->n_client_lang_error);
		}
		break;
	case FROM_PROXY:
		// TODO?
		break;
	case FROM_IUDF:
		if (ret == 0 && is_success) {
			if (UDF_OP_IS_READ(op)) {
				// Note - this would be weird, since there's nowhere for a
				// response to go in our current UDF scans & queries.
				cf_atomic_int_incr(&ns->n_udf_sub_lang_read_success);
			}
			else if (UDF_OP_IS_DELETE(op)) {
				cf_atomic_int_incr(&ns->n_udf_sub_lang_delete_success);
			}
			else if (UDF_OP_IS_WRITE (op)) {
				cf_atomic_int_incr(&ns->n_udf_sub_lang_write_success);
			}
		}
		else {
			cf_info(AS_UDF, "lua error, ret:%d", ret);
			cf_atomic_int_incr(&ns->n_udf_sub_lang_error);
		}
		break;
	case FROM_BATCH:
	case FROM_NSUP:
	default:
		cf_crash(AS_UDF, "unexpected transaction origin %u", origin);
		break;
	}
}


//==========================================================
// Local helpers - construct response to be sent to origin.
//

void
process_failure_str(udf_call* call, const char* err_str, size_t len,
		cf_dyn_buf* db)
{
	if (! err_str) {
		// Better than sending an as_string with null value.
		process_failure(call, NULL, db);
		return;
	}

	as_string stack_s;
	as_string_init_wlen(&stack_s, (char*)err_str, len, false);

	process_failure(call, as_string_toval(&stack_s), db);
}


void
process_result(const as_result* result, udf_call* call, cf_dyn_buf* db)
{
	as_val* val = result->value;

	if (result->is_success) {
		process_success(call, val, db);
		return;
	}

	// Failures...

	if (as_val_type(val) == AS_STRING) {
		process_udf_failure(call, as_string_fromval(val), db);
		return;
	}

	char lua_err_str[1024];
	size_t len = (size_t)sprintf(lua_err_str,
			"%s:0: in function %s() - error() argument type not handled",
			call->def->filename, call->def->function);

	call->tr->result_code = AS_PROTO_RESULT_FAIL_UDF_EXECUTION;
	process_failure_str(call, lua_err_str, len, db);
}


void
process_udf_failure(udf_call* call, const as_string* s, cf_dyn_buf* db)
{
	char* val = as_string_tostring(s);
	size_t vlen = as_string_len((as_string*)s);
	// TODO - make as_string_len() take const.

	long error_code = ldt_get_error_code(val, vlen);

	if (error_code != AS_PROTO_RESULT_FAIL_NOTFOUND &&
			error_code != AS_PROTO_RESULT_FAIL_COLLECTION_ITEM_NOT_FOUND) {
		call->tr->result_code = AS_PROTO_RESULT_FAIL_UDF_EXECUTION;
		process_failure(call, as_string_toval(s), db);
		return;
	}

	call->tr->result_code = (uint8_t)error_code;

	// Send an "empty" response, with no failure bin.

	as_transaction* tr = call->tr;

	size_t msg_sz = 0;
	uint8_t* msgp = (uint8_t*)as_msg_make_response_msg(tr->result_code,
			0, 0, NULL, NULL, 0, tr->rsv.ns, NULL, &msg_sz,
			as_transaction_trid(tr), NULL);

	if (! msgp)	{
		cf_warning_digest(AS_RW, &tr->keyd,
				"{%s} LDT UDF failed to make response msg ",
				tr->rsv.ns->name);
		return;
	}

	db->buf = msgp;
	db->is_stack = false;
	db->alloc_sz = msg_sz;
	db->used_sz = msg_sz;
}


void
process_response(udf_call* call, const char* bin_name, const as_val* val,
		cf_dyn_buf* db)
{
	// No response for background (internal) UDF.
	if (call->def->type == AS_UDF_OP_BACKGROUND) {
		return;
	}

	as_transaction* tr = call->tr;

	// Note - this function quietly handles a null val. The response call will
	// be given a bin with a name but not 'in use', and it does the right thing.

	as_bin stack_bin;
	as_bin* bin = &stack_bin;

	uint32_t particle_size = as_particle_size_from_asval(val);

	static const size_t MAX_STACK_SIZE = 32 * 1024;
	uint8_t stack_particle[particle_size > MAX_STACK_SIZE ? 0 : particle_size];
	uint8_t* particle_buf = stack_particle;

	if (particle_size > MAX_STACK_SIZE) {
		particle_buf = (uint8_t*)cf_malloc(particle_size);

		if (! particle_buf) {
			cf_warning(AS_UDF, "failed alloc particle size %u", particle_size);
			tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
			return;
		}
	}

	as_namespace* ns = tr->rsv.ns;

	as_bin_init(ns, bin, bin_name);
	as_bin_particle_stack_from_asval(bin, particle_buf, val);

	size_t msg_sz = 0;
	uint8_t* msgp = (uint8_t *)as_msg_make_response_msg(tr->result_code,
			tr->generation, tr->void_time, NULL, &bin, 1, ns, NULL, &msg_sz,
			as_transaction_trid(tr), NULL);

	if (! msgp)	{
		cf_warning(AS_RW, "failed to make response msg");

		if (particle_buf != stack_particle) {
			cf_free(particle_buf);
		}

		tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
		return;
	}

	db->buf = msgp;
	db->is_stack = false;
	db->alloc_sz = msg_sz;
	db->used_sz = msg_sz;

	if (particle_buf != stack_particle) {
		cf_free(particle_buf);
	}
}
