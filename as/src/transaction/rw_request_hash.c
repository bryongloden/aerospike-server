/*
 * rw_request_hash.c
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

#include "transaction/rw_request_hash.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"

#include "fault.h"
#include "msg.h"
#include "rchash.h"
#include "util.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/proto.h"
#include "base/transaction.h"
#include "base/transaction_policy.h"
#include "base/xdr_serverside.h"
#include "fabric/fabric.h"
#include "fabric/paxos.h"
#include "transaction/duplicate_resolve.h"
#include "transaction/replica_write.h"
#include "transaction/rw_request.h"
#include "transaction/rw_utils.h"


//==========================================================
// Typedefs & constants.
//

const msg_template rw_mt[] = {
		{ RW_FIELD_OP, M_FT_UINT32 },
		{ RW_FIELD_RESULT, M_FT_UINT32 },
		{ RW_FIELD_NAMESPACE, M_FT_BUF },
		{ RW_FIELD_NS_ID, M_FT_UINT32 },
		{ RW_FIELD_GENERATION, M_FT_UINT32 },
		{ RW_FIELD_DIGEST, M_FT_BUF },
		{ RW_FIELD_VINFOSET, M_FT_BUF },
		{ RW_FIELD_AS_MSG, M_FT_BUF },
		{ RW_FIELD_CLUSTER_KEY, M_FT_UINT64 },
		{ RW_FIELD_RECORD, M_FT_BUF },
		{ RW_FIELD_TID, M_FT_UINT32 },
		{ RW_FIELD_VOID_TIME, M_FT_UINT32 },
		{ RW_FIELD_INFO, M_FT_UINT32 },
		{ RW_FIELD_REC_PROPS, M_FT_BUF },
		{ RW_FIELD_MULTIOP, M_FT_BUF },
		{ RW_FIELD_LDT_VERSION, M_FT_UINT64 },
		{ RW_FIELD_LAST_UPDATE_TIME, M_FT_UINT64 }
};

COMPILER_ASSERT(sizeof(rw_mt) / sizeof(msg_template) == NUM_RW_FIELDS);

#define RW_MSG_SCRATCH_SIZE 280 // 128 + 152 for prole deletes


//==========================================================
// Forward Declarations.
//

uint32_t rw_request_hash_fn(void* value, uint32_t value_len);
transaction_status handle_hot_key(rw_request* rw0, as_transaction* tr);

void* run_retransmit(void* arg);
int retransmit_reduce_fn(void* key, uint32_t keylen, void* data, void* udata);

void on_paxos_change(as_paxos_generation gen, as_paxos_change* change,
		cf_node succession[], void* udata);
int paxos_change_reduce_fn(void* key, uint32_t keylen, void* data, void* udata);
int paxos_change_delete_reduce_fn(void* key, uint32_t keylen, void* data,
		void* udata);

int rw_msg_cb(cf_node id, msg* m, void* udata);


//==========================================================
// Globals.
//

static rchash* g_rw_request_hash = NULL;


//==========================================================
// Public API.
//

void
as_rw_init()
{
	rchash_create(&g_rw_request_hash, rw_request_hash_fn, rw_request_hdestroy,
			sizeof(rw_request_hkey), 32 * 1024, RCHASH_CR_MT_MANYLOCK);

	pthread_t thread;
	pthread_attr_t attrs;

	pthread_attr_init(&attrs);
	pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&thread, &attrs, run_retransmit, NULL) != 0) {
		cf_crash(AS_RW, "failed to create retransmit thread");
	}

	as_paxos_register_change_callback(on_paxos_change, NULL);

	as_fabric_register_msg_fn(M_TYPE_RW, rw_mt, sizeof(rw_mt),
			RW_MSG_SCRATCH_SIZE, rw_msg_cb, NULL);
}


uint32_t
rw_request_hash_count()
{
	return rchash_get_size(g_rw_request_hash);
}


transaction_status
rw_request_hash_insert(rw_request_hkey* hkey, rw_request* rw,
		as_transaction* tr)
{
	int insert_rv;

	while ((insert_rv = rchash_put_unique(g_rw_request_hash, hkey,
			sizeof(*hkey), rw)) != RCHASH_OK) {

		if (insert_rv != RCHASH_ERR_FOUND) {
			tr->result_code = AS_PROTO_RESULT_FAIL_UNKNOWN; // malloc failure
			return TRANS_DONE_ERROR;
		}
		// else - rw_request with this digest already in hash - get it.

		rw_request* rw0;
		int get_rv = rchash_get(g_rw_request_hash, hkey, sizeof(*hkey),
				(void**)&rw0);

		if (get_rv == RCHASH_ERR_NOTFOUND) {
			// Try insertion again immediately.
			continue;
		}
		// else - got it - handle "hot key" scenario.
		cf_assert(get_rv == RCHASH_OK, AS_RW, CF_CRITICAL, "rchash_get error");

		pthread_mutex_lock(&rw0->lock);

		transaction_status status = handle_hot_key(rw0, tr);

		pthread_mutex_unlock(&rw0->lock);
		rw_request_release(rw0);

		return status; // rw_request was not inserted in the hash
	}

	return TRANS_IN_PROGRESS; // rw_request was inserted in the hash
}


void
rw_request_hash_delete(rw_request_hkey* hkey, rw_request* rw)
{
	rchash_delete_object(g_rw_request_hash, hkey, sizeof(*hkey), rw);
}


rw_request*
rw_request_hash_get(rw_request_hkey* hkey)
{
	rw_request* rw = NULL;

	rchash_get(g_rw_request_hash, hkey, sizeof(*hkey), (void**)&rw);

	return rw;
}


// For debugging only.
void
rw_request_hash_dump()
{
	cf_info(AS_RW, "rw_request_hash dump not yet implemented");
	// TODO - implement something, or deprecate.
}


//==========================================================
// Local helpers - hash insertion.
//

uint32_t
rw_request_hash_fn(void* value, uint32_t value_len)
{
	rw_request_hkey* hkey = (rw_request_hkey*)value;

	// TODO - surely this can be simpler, use 4 bytes???
	return	(hkey->keyd.digest[DIGEST_SCRAMBLE_BYTE1] << 16) |
			(hkey->keyd.digest[DIGEST_SCRAMBLE_BYTE2] << 8) |
			(hkey->keyd.digest[DIGEST_SCRAMBLE_BYTE3]);
}


transaction_status
handle_hot_key(rw_request* rw0, as_transaction* tr)
{
	if (rw0->is_set_up &&
			rw0->origin == FROM_PROXY && tr->origin == FROM_PROXY &&
			rw0->from.proxy_node == tr->from.proxy_node &&
			rw0->from_data.proxy_tid == tr->from_data.proxy_tid) {
		// If the new transaction is a retransmitted proxy request, don't
		// queue it or reply to origin, just drop it and feign success.

		return TRANS_DONE_SUCCESS;
	}
	else if (g_config.transaction_pending_limit != 0 &&
			rw_request_wait_q_depth(rw0) > g_config.transaction_pending_limit) {
		// If we're over the hot key pending limit, fail this transaction.
		cf_atomic64_incr(&tr->rsv.ns->n_fail_key_busy);
		tr->result_code = AS_PROTO_RESULT_FAIL_KEY_BUSY;

		return TRANS_DONE_ERROR;
	}
	else {
		// Queue this transaction on the original rw_request - it will be
		// retried when the original is complete.

		rw_wait_ele* e = cf_malloc(sizeof(rw_wait_ele));
		cf_assert(e, AS_RW, CF_CRITICAL, "alloc rw_wait_ele");

		as_transaction_copy_head(&e->tr, tr);
		tr->from.any = NULL;
		tr->msgp = NULL;

		e->next = rw0->wait_queue_head;
		rw0->wait_queue_head = e;

		return TRANS_WAITING;
	}
}


//==========================================================
// Local helpers - retransmit.
//

void*
run_retransmit(void* arg)
{
	while (true) {
		usleep(130 * 1000);

		now_times now;

		now.now_ns = cf_getns();
		now.now_ms = now.now_ns / 1000000;

		rchash_reduce(g_rw_request_hash, retransmit_reduce_fn, &now);
	}

	return NULL;
}


int
retransmit_reduce_fn(void* key, uint32_t keylen, void* data, void* udata)
{
	rw_request* rw = data;
	now_times* now = (now_times*)udata;

	if (! rw->is_set_up) {
		return 0;
	}

	if (now->now_ns > rw->end_time) {
		pthread_mutex_lock(&rw->lock);

		rw->timeout_cb(rw);

		pthread_mutex_unlock(&rw->lock);

		return RCHASH_REDUCE_DELETE;
	}

	if (rw->xmit_ms < now->now_ms) {
		pthread_mutex_lock(&rw->lock);

		rw->xmit_ms = now->now_ms + rw->retry_interval_ms;
		rw->retry_interval_ms *= 2;

		send_rw_messages(rw);

		pthread_mutex_unlock(&rw->lock);
	}

	return 0;
}


//==========================================================
// Local helpers - handle paxos changed events.
//

void
on_paxos_change(as_paxos_generation gen, as_paxos_change* change,
		cf_node succession[], void* udata)
{
	if (change->n_change != 1 || change->type[0] != AS_PAXOS_CHANGE_SYNC) {
		cf_crash(AS_RW, "unexpected paxos-changed event data");
	}

	rw_paxos_change_struct del;

	memset(&del, 0, sizeof(rw_paxos_change_struct));
	memcpy(del.succession, succession,
			sizeof(cf_node) * g_config.paxos_max_cluster_size);

	// Update the XDR cluster map. Piggybacking on this callback instead of
	// adding a new one.
	xdr_clmap_update(AS_PAXOS_CHANGE_SYNC, succession,
			g_config.paxos_max_cluster_size);

	// Iterate through the hash table and find nodes that are not in the
	// succession list. Remove these entries from the hash table.
	rchash_reduce(g_rw_request_hash, paxos_change_reduce_fn, (void*)&del);

	// If there are nodes to be deleted, execute the deletion algorithm.
	for (int i = 0; i < g_config.paxos_max_cluster_size; i++) {
		if (del.deletions[i] != (cf_node)0) {
			rchash_reduce(g_rw_request_hash, paxos_change_delete_reduce_fn,
					(void*)&del.deletions[i]);
		}
	}
}


int
paxos_change_reduce_fn(void* key, uint32_t keylen, void* data, void* udata)
{
	rw_request* rw = (rw_request*)data;
	rw_paxos_change_struct* del = (rw_paxos_change_struct*)udata;
	bool node_in_slist = false;

	for (int i = 0; i < rw->n_dest_nodes; i++) {
		// Check if this key is in the succession list.
		node_in_slist = false;

		for (int j = 0; j < g_config.paxos_max_cluster_size; j++) {
			if (rw->dest_nodes[i] == del->succession[j]) {
				node_in_slist = true;
				break;
			}
		}

		if (! node_in_slist) {
			for (int j = 0; j < g_config.paxos_max_cluster_size; j++) {
				// If an empty slot exists, then it means key is not there yet.
				if (del->deletions[j] == (cf_node)0) {
					del->deletions[j] = rw->dest_nodes[i];
					break;
				}

				// If key already exists, return.
				if (rw->dest_nodes[i] == del->deletions[i]) {
					break;
				}
			}
		}
	}

	return 0;
}


int
paxos_change_delete_reduce_fn(void* key, uint32_t keylen, void* data,
		void* udata)
{
	rw_request* rw = (rw_request*)data;
	cf_node* node = (cf_node*)udata;

	for (int i = 0; i < rw->n_dest_nodes; i++) {
		if (! rw->dest_complete[i] && rw->dest_nodes[i] == *node) {
			rw->xmit_ms = 0;
		}
	}

	return 0;
}


//==========================================================
// Local helpers - handle RW fabric messages.
//

int
rw_msg_cb(cf_node id, msg* m, void* udata)
{
	uint32_t op;

	if (msg_get_uint32(m, RW_FIELD_OP, &op) != 0) {
		cf_warning(AS_RW, "got rw msg without op field");
		as_fabric_msg_put(m);
		return 0;
	}

	switch (op) {
	//--------------------------------------------
	// Duplicate resolution:
	//
	case RW_OP_DUP:
		dup_res_handle_request(id, m);
		break;
	case RW_OP_DUP_ACK:
		dup_res_handle_ack(id, m);
		break;

	//--------------------------------------------
	// Replica writes:
	//
	case RW_OP_WRITE:
		repl_write_handle_op(id, m);
		break;
	case RW_OP_WRITE_ACK:
		repl_write_handle_ack(id, m);
		break;

	//--------------------------------------------
	// LDT-related:
	//
	case RW_OP_MULTI:
		{
			uint64_t start_ns = g_config.ldt_benchmarks ?  cf_getns() : 0;

			repl_write_handle_multiop(id, m);

			if (start_ns != 0) {
				histogram_insert_data_point(g_stats.ldt_multiop_prole_hist,
						start_ns);
			}
		}
		break;
	case RW_OP_MULTI_ACK:
		repl_write_handle_multiop_ack(id, m);
		break;

	default:
		cf_warning(AS_RW, "got rw msg with unrecognized op %u", op);
		as_fabric_msg_put(m);
		break;
	}

	return 0;
}
