/*
 * read.c
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

#include "transaction/read.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"

#include "dynbuf.h"
#include "fault.h"

#include "base/batch.h"
#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/thr_proxy.h"
#include "base/transaction.h"
#include "base/transaction_policy.h"
#include "storage/storage.h"
#include "transaction/duplicate_resolve.h"
#include "transaction/rw_request.h"
#include "transaction/rw_request_hash.h"
#include "transaction/rw_utils.h"


//==========================================================
// Forward Declarations.
//

transaction_status start_read_dup_res(as_transaction* tr, bool send_metadata);
bool read_after_dup_res(rw_request* rw);
void read_local(as_transaction* tr, bool stop_if_not_found);
void read_local_done(as_transaction* tr, as_index_ref* r_ref, as_storage_rd* rd,
		int result_code);
void send_read_response(as_transaction* tr, as_msg_op** ops,
		as_bin** response_bins, uint16_t n_bins, uint32_t generation,
		uint32_t void_time, const char* set_name);
void read_timeout(rw_request* rw);


//==========================================================
// Public API.
//

transaction_status
as_read_start(as_transaction* tr)
{
	// If there are duplicates and we always resolve them, start doing so.
	if (tr->rsv.n_dupl != 0 &&
			(g_config.transaction_repeatable_read ||
					TRANSACTION_CONSISTENCY_LEVEL(tr) ==
							AS_POLICY_CONSISTENCY_LEVEL_ALL)) {
		return start_read_dup_res(tr, true);
	}

	// Try to read local copy. If record is found or there are no duplicates,
	// response is sent to origin.
	read_local(tr, tr->rsv.n_dupl != 0);

	// If no local copy was found, fetch possible duplicates.
	if (tr->rsv.n_dupl != 0 &&
			tr->result_code == AS_PROTO_RESULT_FAIL_NOTFOUND) {
		return start_read_dup_res(tr, false);
	}

	// We don't need duplicate resolution, transaction is finished.
	// Note - transaction may have failed, but response has been sent, so as far
	// as thr_tsvc is concerned, it looks like a success.
	return TRANS_DONE_SUCCESS;
}


//==========================================================
// Local helpers.
//

transaction_status
start_read_dup_res(as_transaction* tr, bool send_metadata)
{
	// Create rw_request and add to hash.
	rw_request_hkey hkey = { tr->rsv.ns->id, tr->keyd };
	rw_request* rw = rw_request_create(&tr->keyd);
	transaction_status status = rw_request_hash_insert(&hkey, rw, tr);

	// If rw_request wasn't inserted in hash, transaction is finished.
	if (status != TRANS_IN_PROGRESS) {
		rw_request_release(rw);

		if (status != TRANS_WAITING) {
			send_read_response(tr, NULL, NULL, 0, 0, 0, NULL);
		}

		return status;
	}
	// else - rw_request is now in hash, continue...

	// Finish initializing rw_request, construct and send dup-res message.

	if (! dup_res_make_message(rw, tr, send_metadata)) {
		rw_request_hash_delete(&hkey);
		tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN;
		send_read_response(tr, NULL, NULL, 0, 0, 0, NULL);
		return TRANS_DONE_ERROR;
	}

	rw->timeout_cb = read_timeout;

	pthread_mutex_lock(&rw->lock);

	dup_res_setup_rw(rw, tr, read_after_dup_res);
	send_rw_messages(rw);

	pthread_mutex_unlock(&rw->lock);

	// Started duplicate resolution.
	return TRANS_IN_PROGRESS;
}


bool
read_after_dup_res(rw_request* rw)
{
	as_transaction tr;
	as_transaction_init_from_rw(&tr, rw);

	// Read the local copy and respond to origin.
	read_local(&tr, false);

	// Finished transaction - rw_request cleans up reservation and msgp!
	return true;
}


void
read_local(as_transaction* tr, bool stop_if_not_found)
{
	as_msg* m = &tr->msgp->msg;
	as_namespace* ns = tr->rsv.ns;

	as_index_ref r_ref;
	r_ref.skip_lock = false;

	if (as_record_get(tr->rsv.tree, &tr->keyd, &r_ref, ns) != 0) {
		if (stop_if_not_found) {
			tr->result_code = AS_PROTO_RESULT_FAIL_NOTFOUND;
			return;
		}

		read_local_done(tr, NULL, NULL, AS_PROTO_RESULT_FAIL_NOTFOUND);
		return;
	}

	as_record* r = r_ref.r;
	as_storage_rd rd;

	as_storage_record_open(ns, r, &rd, &tr->keyd);

	// Check if it's an expired record.
	if (as_record_is_expired(r)) {
		read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_NOTFOUND);
		return;
	}

	// Check the key if required.
	// Note - for data-not-in-memory "exists" ops, key check is expensive!
	if (as_transaction_has_key(tr) &&
			as_storage_record_get_key(&rd) && ! check_msg_key(m, &rd)) {
		read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_KEY_MISMATCH);
		return;
	}

	if ((m->info1 & AS_MSG_INFO1_GET_NOBINDATA) != 0) {
		read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_OK);
		return;
	}

	rd.n_bins = as_bin_get_n_bins(r, &rd);

	as_bin stack_bins[ns->storage_data_in_memory ? 0 : rd.n_bins];

	rd.bins = as_bin_get_all(r, &rd, stack_bins);

	if (! as_bin_inuse_has(&rd)) {
		cf_warning_digest(AS_RW, &tr->keyd, "{%s} read_local: found record with no bins ", ns->name);
		read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_NOTFOUND);
		return;
	}

	uint32_t bin_count = (m->info1 & AS_MSG_INFO1_GET_ALL) != 0 ?
			rd.n_bins : m->n_ops;

	as_msg_op* ops[bin_count];
	as_msg_op** p_ops = ops;
	as_bin* response_bins[bin_count];
	uint16_t n_bins = 0;

	as_bin result_bins[bin_count];
	uint32_t n_result_bins = 0;

	if ((m->info1 & AS_MSG_INFO1_GET_ALL) != 0) {
		p_ops = NULL;
		n_bins = as_bin_inuse_count(&rd);
		as_bin_get_all_p(&rd, response_bins);
	}
	else {
		if (m->n_ops == 0) {
			cf_warning_digest(AS_RW, &tr->keyd, "{%s} read_local: bin op(s) expected, none present ", ns->name);
			read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_PARAMETER);
			return;
		}

		bool respond_all_ops = (m->info2 & AS_MSG_INFO2_RESPOND_ALL_OPS) != 0;
		int result;

		as_msg_op* op = 0;
		int n = 0;

		while ((op = as_msg_op_iterate(m, op, &n)) != NULL) {
			if (op->op == AS_MSG_OP_READ) {
				as_bin* b = as_bin_get_from_buf(&rd, op->name, op->name_sz);

				if (b || respond_all_ops) {
					ops[n_bins] = op;
					response_bins[n_bins++] = b;
				}
			}
			else if (op->op == AS_MSG_OP_CDT_READ) {
				as_bin* b = as_bin_get_from_buf(&rd, op->name, op->name_sz);

				if (b) {
					as_bin* rb = &result_bins[n_result_bins];
					as_bin_set_empty(rb);

					if ((result = as_bin_cdt_read_from_client(b, op, rb)) < 0) {
						cf_warning_digest(AS_RW, &tr->keyd, "{%s} read_local: failed as_bin_cdt_read_from_client() ", ns->name);
						destroy_stack_bins(result_bins, n_result_bins);
						read_local_done(tr, &r_ref, &rd, -result);
						return;
					}

					if (as_bin_inuse(rb)) {
						b = rb;
						n_result_bins++;
					}
				}

				if (b || respond_all_ops) {
					ops[n_bins] = op;
					response_bins[n_bins++] = b;
				}
			}
			else {
				cf_warning_digest(AS_RW, &tr->keyd, "{%s} read_local: unexpected bin op %u ", ns->name, op->op);
				destroy_stack_bins(result_bins, n_result_bins);
				read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_PARAMETER);
				return;
			}
		}
	}

	const char* set_name = (m->info1 & AS_MSG_INFO1_XDR) != 0 ?
			as_index_get_set_name(r, ns) : NULL;

	// Container to allow use of as_msg_send_ops_reply(), until we refactor and
	// clean up single transaction response handling generally.
	cf_dyn_buf_define_size(db, 16 * 1024);

	// Note - don't really need proto_fd_h check since we bailed early on losing
	// race vs. timeout.
	if (tr->origin == FROM_CLIENT && tr->from.proto_fd_h) {
		// Single out the client transaction case for now - others don't need
		// this special handling (as urgently) for various reasons.

		db.used_sz = db.alloc_sz;
		db.buf = (uint8_t*)as_msg_make_response_msg(tr->result_code,
				r->generation, r->void_time, p_ops, response_bins, n_bins, ns,
				(cl_msg*)dyn_bufdb, &db.used_sz, as_transaction_trid(tr),
				set_name);

		if (! db.buf)	{
			cf_warning_digest(AS_RW, &tr->keyd, "{%s} read_local: failed make response msg ", ns->name);
			destroy_stack_bins(result_bins, n_result_bins);
			read_local_done(tr, &r_ref, &rd, AS_PROTO_RESULT_FAIL_UNKNOWN);
			return;
		}

		db.is_stack = db.buf == dyn_bufdb;
		// Note - not bothering to correct alloc_sz if buf was allocated.
	}
	else {
		send_read_response(tr, p_ops, response_bins, n_bins, r->generation,
				r->void_time, set_name);
	}

	destroy_stack_bins(result_bins, n_result_bins);
	as_storage_record_close(r, &rd);
	as_record_done(&r_ref, ns);

	// Now that we're not under the record lock, send the message we just built.
	if (db.used_sz != 0) {
		// Using the function for write responses for now.
		as_msg_send_ops_reply(tr->from.proto_fd_h, &db);

		cf_dyn_buf_free(&db);
		tr->from.proto_fd_h = NULL;
	}
}


void
read_local_done(as_transaction* tr, as_index_ref* r_ref, as_storage_rd* rd,
		int result_code)
{
	uint32_t generation = 0;
	uint32_t void_time = 0;

	if (r_ref) {
		if (rd) {
			as_storage_record_close(r_ref->r, rd);
		}

		generation = r_ref->r->generation;
		void_time = r_ref->r->void_time;

		as_record_done(r_ref, tr->rsv.ns);
	}

	tr->result_code = (uint8_t)result_code;

	send_read_response(tr, NULL, NULL, 0, generation, void_time, NULL);
}


void
send_read_response(as_transaction* tr, as_msg_op** ops, as_bin** response_bins,
		uint16_t n_bins, uint32_t generation, uint32_t void_time,
		const char* set_name)
{
	// We don't need the tr->from check since we're protected against the race
	// with timeout via exit clause in the dup-res ack handling, but follow the
	// pattern.

	switch (tr->origin) {
	case FROM_CLIENT:
		if (tr->from.proto_fd_h) {
			as_msg_send_reply(tr->from.proto_fd_h, tr->result_code, generation,
					void_time, ops, response_bins, n_bins, tr->rsv.ns, NULL,
					as_transaction_trid(tr), set_name);
			tr->from.proto_fd_h = NULL;
		}
		break;
	case FROM_PROXY:
		if (tr->from.proxy_node != 0) {
			as_proxy_send_response(tr->from.proxy_node, tr->from_data.proxy_tid,
					tr->result_code, generation, void_time, ops, response_bins,
					n_bins, tr->rsv.ns, as_transaction_trid(tr), set_name);
			tr->from.proxy_node = 0;
		}
		break;
	case FROM_BATCH:
		if (tr->from.batch_shared) {
			as_batch_add_result(tr, tr->rsv.ns, set_name, generation, void_time,
					n_bins, response_bins, ops);
			tr->from.batch_shared = NULL;
			// as_batch_add_result zeroed tr->msgp.
		}
		break;
	case FROM_IUDF:
	case FROM_NSUP:
		// Should be impossible for internal UDFs and nsup deletes to get here.
	default:
		cf_crash(AS_PROXY, "unexpected transaction origin %u", tr->origin);
		break;
	}
}


void
read_timeout(rw_request* rw)
{
	switch (rw->origin) {
	case FROM_CLIENT:
		if (rw->from.proto_fd_h) {
			as_end_of_transaction_force_close(rw->from.proto_fd_h);
			rw->from.proto_fd_h = NULL;
		}
		break;
	case FROM_PROXY:
		rw->from.proxy_node = 0;
		break;
	case FROM_BATCH:
		if (rw->from.batch_shared) {
			as_batch_add_error(rw->from.batch_shared, rw->from_data.batch_index,
					AS_PROTO_RESULT_FAIL_TIMEOUT);
			rw->from.batch_shared = NULL;
			rw->msgp = NULL;
		}
		break;
	case FROM_IUDF:
	case FROM_NSUP:
		// Should be impossible for internal UDFs and nsup deletes to get here.
		break;
	default:
		cf_crash(AS_RW, "unexpected transaction origin %u", rw->origin);
		break;
	}
}