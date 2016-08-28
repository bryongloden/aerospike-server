/*
 * duplicate_resolve.c
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

#include "transaction/duplicate_resolve.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_digest.h"

#include "fault.h"
#include "msg.h"
#include "util.h"

#include "base/datamodel.h"
#include "base/ldt.h"
#include "base/proto.h"
#include "base/thr_tsvc.h"
#include "base/transaction.h"
#include "fabric/fabric.h"
#include "storage/storage.h"
#include "transaction/rw_request.h"
#include "transaction/rw_request_hash.h"


//==========================================================
// Forward Declarations.
//

void done_handle_request(as_partition_reservation* rsv, as_index_ref* r_ref);
void send_dup_res_ack(cf_node node, msg* m, uint32_t result);
void send_ack_for_bad_request(cf_node node, msg* m);
bool apply_winner(rw_request* rw);
void get_ldt_info(const msg* m, as_record_merge_component* c);


//==========================================================
// Public API.
//

bool
dup_res_make_message(rw_request* rw, as_transaction* tr, bool send_metadata)
{
	if (! (rw->dest_msg = as_fabric_msg_get(M_TYPE_RW))) {
		return false;
	}

	as_namespace* ns = tr->rsv.ns;
	msg* m = rw->dest_msg;

	msg_set_uint32(m, RW_FIELD_OP, RW_OP_DUP);
	msg_set_buf(m, RW_FIELD_NAMESPACE, (uint8_t*)ns->name, strlen(ns->name),
			MSG_SET_COPY);
	msg_set_uint32(m, RW_FIELD_NS_ID, ns->id);
	msg_set_buf(m, RW_FIELD_DIGEST, (void*)&tr->keyd, sizeof(cf_digest),
			MSG_SET_COPY);
	msg_set_uint64(m, RW_FIELD_CLUSTER_KEY, tr->rsv.cluster_key);
	msg_set_uint32(m, RW_FIELD_TID, rw->tid);

	if (send_metadata) {
		as_index_ref r_ref;
		r_ref.skip_lock = false;

		if (as_record_get(tr->rsv.tree, &tr->keyd, &r_ref, ns) == 0) {
			as_record* r = r_ref.r;

			msg_set_uint32(m, RW_FIELD_GENERATION, r->generation);
			msg_set_uint32(m, RW_FIELD_VOID_TIME, r->void_time);
			msg_set_uint64(m, RW_FIELD_LAST_UPDATE_TIME, r->last_update_time);

			as_record_done(&r_ref, ns);
		}
	}

	return true;
}


void
dup_res_setup_rw(rw_request* rw, as_transaction* tr, dup_res_done_cb dup_res_cb,
		timeout_done_cb timeout_cb)
{
	rw->msgp = tr->msgp;
	tr->msgp = NULL;

	rw->msg_fields = tr->msg_fields;
	rw->origin = tr->origin;
	rw->from_flags = tr->from_flags;

	rw->from.any = tr->from.any;
	rw->from_data.any = tr->from_data.any;
	tr->from.any = NULL;

	rw->start_time = tr->start_time;
	rw->benchmark_time = tr->benchmark_time;

	as_partition_reservation_copy(&rw->rsv, &tr->rsv);
	// Hereafter, rw must release the reservation - happens in destructor.

	rw->end_time = tr->end_time;
	// Note - don't need as_transaction's other 'container' members.

	rw->dup_res_cb = dup_res_cb;
	rw->timeout_cb = timeout_cb;

	rw->xmit_ms = cf_getms() + g_config.transaction_retry_ms;
	rw->retry_interval_ms = g_config.transaction_retry_ms;

	rw->n_dest_nodes = tr->rsv.n_dupl;

	for (int i = 0; i < rw->n_dest_nodes; i++) {
		rw->dest_complete[i] = false;
		rw->dest_nodes[i] = tr->rsv.dupl_nodes[i];
		rw->dup_msg[i] = NULL;
		rw->dup_result_code[i] = 0;
	}

	// Allow retransmit thread to destroy rw as soon as we unlock.
	rw->is_set_up = true;
}


void
dup_res_handle_request(cf_node node, msg* m)
{
	cf_digest* keyd;
	size_t sz = 0;

	if (msg_get_buf(m, RW_FIELD_DIGEST, (uint8_t**)&keyd, &sz,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "dup-res handler: no digest");
		send_ack_for_bad_request(node, m);
		return;
	}

	uint64_t cluster_key;

	if (msg_get_uint64(m, RW_FIELD_CLUSTER_KEY, &cluster_key) != 0) {
		cf_warning(AS_RW, "dup-res handler: no cluster key");
		send_ack_for_bad_request(node, m);
		return;
	}

	uint8_t* ns_name;
	size_t ns_name_len;

	if (0 != msg_get_buf(m, RW_FIELD_NAMESPACE, &ns_name, &ns_name_len,
			MSG_GET_DIRECT)) {
		cf_warning(AS_RW, "dup-res handler: no namespace");
		send_ack_for_bad_request(node, m);
		return;
	}

	as_namespace* ns = as_namespace_get_bybuf(ns_name, ns_name_len);

	if (! ns) {
		cf_warning(AS_RW, "dup-res handler: invalid namespace");
		send_ack_for_bad_request(node, m);
		return;
	}

	uint32_t generation = 0;
	uint32_t void_time = 0;
	bool local_conflict_check =
			msg_get_uint32(m, RW_FIELD_GENERATION, &generation) == 0 &&
			msg_get_uint32(m, RW_FIELD_VOID_TIME, &void_time) == 0;

	uint64_t last_update_time = 0;

	// Older nodes won't send this.
	msg_get_uint64(m, RW_FIELD_LAST_UPDATE_TIME, &last_update_time);

	// Done reading message fields, may now set fields for ack.
	msg_preserve_fields(m, 3, RW_FIELD_NS_ID, RW_FIELD_DIGEST, RW_FIELD_TID);

	as_partition_reservation rsv;
	AS_PARTITION_RESERVATION_INIT(rsv); // TODO - not really needed?

	as_partition_reserve_migrate(ns, as_partition_getid(*keyd), &rsv, NULL);

	if (rsv.cluster_key != cluster_key) {
		done_handle_request(&rsv, NULL);
		send_dup_res_ack(node, m, AS_PROTO_RESULT_FAIL_CLUSTER_KEY_MISMATCH);
		return;
	}

	as_index_ref r_ref;
	r_ref.skip_lock = false;

	if (as_record_get(rsv.tree, keyd, &r_ref, ns) != 0) {
		done_handle_request(&rsv, NULL);
		send_dup_res_ack(node, m, AS_PROTO_RESULT_FAIL_NOTFOUND);
		return;
	}

	as_record* r = r_ref.r;

	if (local_conflict_check &&
			0 >= as_record_resolve_conflict(ns->conflict_resolution_policy,
					generation, last_update_time, void_time,
					r->generation, r->last_update_time, r->void_time)) {
		done_handle_request(&rsv, &r_ref);
		send_dup_res_ack(node, m, AS_PROTO_RESULT_FAIL_NOTFOUND);
		return;
	}

	if (ns->ldt_enabled && as_ldt_record_is_sub(r)) {
		cf_warning(AS_RW, "invalid dup-res request: for ldt subrecord");
		done_handle_request(&rsv, &r_ref);
		send_dup_res_ack(node, m, AS_PROTO_RESULT_FAIL_NOTFOUND); // ???
		return;
	}

	if (ns->ldt_enabled && as_ldt_record_is_parent(r)) {
		msg_set_uint32(m, RW_FIELD_INFO,
				RW_INFO_LDT_PARENTREC | RW_INFO_LDT_DUMMY);
	}
	else {
		as_storage_rd rd;

		as_storage_record_open(ns, r, &rd, keyd);

		rd.n_bins = as_bin_get_n_bins(r, &rd);

		as_bin stack_bins[rd.ns->storage_data_in_memory ? 0 : rd.n_bins];

		rd.bins = as_bin_get_all(r, &rd, stack_bins);

		uint8_t* buf;
		size_t buf_len;

		if (0 != as_record_pickle(r, &rd, &buf, &buf_len)) {
			as_storage_record_close(r, &rd);
			done_handle_request(&rsv, &r_ref);
			send_dup_res_ack(node, m, AS_PROTO_RESULT_FAIL_UNKNOWN);
			return;
		}

		as_storage_record_get_key(&rd);

		size_t rec_props_data_size = as_storage_record_rec_props_size(&rd);
		uint8_t rec_props_data[rec_props_data_size];

		if (rec_props_data_size > 0) {
			as_storage_record_set_rec_props(&rd, rec_props_data);
			msg_set_buf(m, RW_FIELD_REC_PROPS, rd.rec_props.p_data,
					rd.rec_props.size, MSG_SET_COPY);
		}

		as_storage_record_close(r, &rd);

		msg_set_buf(m, RW_FIELD_RECORD, (void*)buf, buf_len,
				MSG_SET_HANDOFF_MALLOC);
	}

	// Note - older versions expect RW_FIELD_VINFOSET, so must send it for now.
	static const uint8_t VINFO_BUF_0[] = { 0, 0, 0, 0 };
	msg_set_buf(m, RW_FIELD_VINFOSET, VINFO_BUF_0, 4, MSG_SET_COPY);

	msg_set_uint32(m, RW_FIELD_GENERATION, r->generation);
	msg_set_uint32(m, RW_FIELD_VOID_TIME, r->void_time);
	msg_set_uint64(m, RW_FIELD_LAST_UPDATE_TIME, r->last_update_time);

	done_handle_request(&rsv, &r_ref);
	send_dup_res_ack(node, m, AS_PROTO_RESULT_OK);
}


void
dup_res_handle_ack(cf_node node, msg* m)
{
	uint32_t ns_id;

	if (msg_get_uint32(m, RW_FIELD_NS_ID, &ns_id) != 0) {
		cf_warning(AS_RW, "dup-res ack: no ns-id");
		as_fabric_msg_put(m);
		return;
	}

	cf_digest* keyd;
	size_t sz;

	if (msg_get_buf(m, RW_FIELD_DIGEST, (uint8_t**)&keyd, &sz,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "dup-res ack: no digest");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t tid;

	if (msg_get_uint32(m, RW_FIELD_TID, &tid) != 0) {
		cf_warning(AS_RW, "dup-res ack: no tid");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t result_code;

	if (msg_get_uint32(m, RW_FIELD_RESULT, &result_code) != 0) {
		cf_warning(AS_RW, "dup-res ack: no result_code");
		as_fabric_msg_put(m);
		return;
	}

	rw_request_hkey hkey = { ns_id, *keyd };
	rw_request* rw = rw_request_hash_get(&hkey);

	if (! rw) {
		// Extra ack, after rw_request is already gone.
		as_fabric_msg_put(m);
		return;
	}

	pthread_mutex_lock(&rw->lock);

	if (rw->tid != tid) {
		// Extra ack, rw_request is that of newer transaction for same digest.
		pthread_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	if (rw->dup_res_complete) {
		// Ack arriving after rw_request was aborted or finished dup-res.
		pthread_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	if (result_code == AS_PROTO_RESULT_FAIL_CLUSTER_KEY_MISMATCH) {
		if (! rw->from.any) {
			// Lost race against timeout in retransmit thread.
			pthread_mutex_unlock(&rw->lock);
			rw_request_release(rw);
			as_fabric_msg_put(m);
			return;
		}

		as_transaction tr;
		as_transaction_init_head_from_rw(&tr, rw);

		// Note that tr now owns msgp - make sure rw destructor doesn't free it.
		// Note also that rw will release rsv - tr will get a new one.
		rw->msgp = NULL;

		tr.from_flags |= FROM_FLAG_RESTART;
		thr_tsvc_enqueue(&tr);

		rw->dup_res_complete = true;

		pthread_mutex_unlock(&rw->lock);
		rw_request_hash_delete(&hkey, rw);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	int i;

	for (i = 0; i < rw->n_dest_nodes; i++) {
		if (rw->dest_nodes[i] != node) {
			continue;
		}

		if (rw->dest_complete[i]) {
			// Extra ack for this duplicate.
			pthread_mutex_unlock(&rw->lock);
			rw_request_release(rw);
			as_fabric_msg_put(m);
			return;
		}

		rw->dest_complete[i] = true;
		rw->dup_result_code[i] = result_code;
		rw->dup_msg[i] = m;

		break;
	}

	if (i == rw->n_dest_nodes) {
		cf_warning(AS_RW, "dup-res ack: from non-dest node %lx", node);
		pthread_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	for (int j = 0; j < rw->n_dest_nodes; j++) {
		if (! rw->dest_complete[j]) {
			// Still haven't heard from all duplicates, so save this response.
			msg_preserve_all_fields(rw->dup_msg[i]);

			pthread_mutex_unlock(&rw->lock);
			rw_request_release(rw);
			// Note - don't call as_fabric_msg_put(m)!
			return;
		}
	}

	bool is_ldt_ship_op = apply_winner(rw);
	// Note - apply_winner() puts all rw->dup_msg[]s including m, so don't call
	// as_fabric_msg_put(m) afterwards.

	rw->dup_res_complete = true;

	if (is_ldt_ship_op) {
		pthread_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		return;
	}

	// Check for lost race against timeout in retransmit thread *after* applying
	// winner - may save a future transaction from re-fetching the duplicates.
	// Note - nsup deletes don't get here, so check using rw->from.any is ok.
	if (! rw->from.any) {
		pthread_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		return;
	}

	bool delete_from_hash = rw->dup_res_cb(rw);

	pthread_mutex_unlock(&rw->lock);

	if (delete_from_hash) {
		rw_request_hash_delete(&hkey, rw);
	}

	rw_request_release(rw);
}


//==========================================================
// Local helpers.
//

void
done_handle_request(as_partition_reservation* rsv, as_index_ref* r_ref)
{
	if (r_ref) {
		as_record_done(r_ref, rsv->ns);
	}

	if (rsv) {
		as_partition_release(rsv);
	}
}


void
send_dup_res_ack(cf_node node, msg* m, uint32_t result)
{
	msg_set_uint32(m, RW_FIELD_OP, RW_OP_DUP_ACK);
	msg_set_uint32(m, RW_FIELD_RESULT, result);

	if (as_fabric_send(node, m, AS_FABRIC_PRIORITY_MEDIUM) !=
			AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}


void
send_ack_for_bad_request(cf_node node, msg* m)
{
	msg_preserve_fields(m, 3, RW_FIELD_NS_ID, RW_FIELD_DIGEST, RW_FIELD_TID);

	msg_set_uint32(m, RW_FIELD_OP, RW_OP_DUP_ACK);
	msg_set_uint32(m, RW_FIELD_RESULT, AS_PROTO_RESULT_FAIL_UNKNOWN); // ???

	if (as_fabric_send(node, m, AS_FABRIC_PRIORITY_MEDIUM) !=
			AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}


bool
apply_winner(rw_request* rw)
{
	int n = 0;
	as_record_merge_component dups[rw->n_dest_nodes];

	memset(&dups, 0, sizeof(dups));

	for (int i = 0; i < rw->n_dest_nodes; i++) {
		msg* m = rw->dup_msg[i];

		if (! m) {
			// We can mark a dest node complete without getting a response.
			continue;
		}

		uint32_t result_code;

		// Already made sure this field is present.
		msg_get_uint32(m, RW_FIELD_RESULT, &result_code);

		if (result_code != AS_PROTO_RESULT_OK) {
			// Typical result here might be NOT_FOUND.
			continue;
		}

		if (msg_get_uint32(m, RW_FIELD_GENERATION, &dups[n].generation) != 0) {
			cf_warning_digest(AS_RW, &rw->keyd, "dup-res ack: no generation ");
			continue;
		}

		if (msg_get_uint32(m, RW_FIELD_VOID_TIME, &dups[n].void_time) != 0) {
			cf_warning_digest(AS_RW, &rw->keyd, "dup-res ack: no void_time ");
			continue;
		}

		// Older nodes won't send this.
		msg_get_uint64(m, RW_FIELD_LAST_UPDATE_TIME, &dups[n].last_update_time);

		if (rw->rsv.ns->ldt_enabled) {
			get_ldt_info(m, &dups[n]);

			if (COMPONENT_IS_LDT(&dups[n])) {
				n++;
				continue;
			}
		}

		if (msg_get_buf(m, RW_FIELD_RECORD, &dups[n].record_buf,
				&dups[n].record_buf_sz, MSG_GET_DIRECT) != 0) {
			cf_warning_digest(AS_RW, &rw->keyd, "dup-res ack: no record ");
			continue;
		}

		// Paranoia only.
		// TODO - should have inline wrapper to peek pickled bin count.
		if (*(uint16_t*)dups[n].record_buf == 0) {
			cf_warning_digest(AS_RW, &rw->keyd, "dup-res ack: binless pickle ");
			continue;
		}

		size_t rec_props_size = 0;

		msg_get_buf(m, RW_FIELD_REC_PROPS, &dups[n].rec_props.p_data,
				&rec_props_size, MSG_GET_DIRECT);
		dups[n].rec_props.size = (uint32_t)rec_props_size;

		n++;
	}

	int rv = 0;
	int winner_idx = -1;

	if (n > 0) {
		rv = as_record_flatten(&rw->rsv, &rw->keyd, n, dups, &winner_idx);
	}

	for (int i = 0; i < rw->n_dest_nodes; i++) {
		if (rw->dup_msg[i]) {
			as_fabric_msg_put(rw->dup_msg[i]);
			rw->dup_msg[i] = NULL;
		}
	}

	// LDT-specific:
	if (rv == -7) {
		if (winner_idx < 0) {
			cf_warning(AS_LDT, "unexpected winner @ index %d.. resorting to 0",
					winner_idx);
			winner_idx = 0;
		}

		cf_detail_digest(AS_RW, &rw->keyd,
				"SHIPPED_OP %s Shipping op to %"PRIx64"",
				rw->origin == FROM_PROXY ? "NONORIG" : "ORIG",
				rw->dest_nodes[winner_idx]);

		as_ldt_shipop(rw, rw->dest_nodes[winner_idx]);

		return true; // Don't delete rw from hash - we're not done with it!
	}

	return false;
}


void
get_ldt_info(const msg* m, as_record_merge_component* c)
{
	c->flag = AS_COMPONENT_FLAG_DUP;

	uint32_t info;

	if (msg_get_uint32(m, RW_FIELD_INFO, &info) != 0) {
		return;
	}

	if ((info & RW_INFO_LDT_PARENTREC) != 0) {
		c->flag |= AS_COMPONENT_FLAG_LDT_REC;
	}

	if ((info & RW_INFO_LDT_DUMMY) != 0) {
		c->flag |= AS_COMPONENT_FLAG_LDT_DUMMY;
	}

	if ((info & RW_INFO_LDT_SUBREC) != 0) {
		c->flag |= AS_COMPONENT_FLAG_LDT_SUBREC;
		cf_warning(AS_RW, "dup-res ack: got subrecord");
	}

	if ((info & RW_INFO_LDT_ESR) != 0) {
		c->flag |= AS_COMPONENT_FLAG_LDT_ESR;
		cf_warning(AS_RW, "dup-res ack: got esr");
	}
}
