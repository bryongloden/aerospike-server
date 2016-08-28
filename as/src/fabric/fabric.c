/*
 * fabric.c
 *
 * Copyright (C) 2008-2016 Aerospike, Inc.
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
 * The interconnect fabric is a means of sending messages throughout
 * the entire system, in order to heal and vote and such
 */

#include "fabric/fabric.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_ll.h"
#include "citrusleaf/cf_queue.h"
#include "citrusleaf/cf_queue_priority.h"
#include "citrusleaf/cf_shash.h"

#include "fault.h"
#include "msg.h"
#include "socket.h"
#include "util.h"

#include "base/cfg.h"
#include "base/stats.h"
#include "fabric/hb.h"
#include "fabric/paxos.h"


// #define EXTRA_CHECKS 1

// Operation to be performed on transaction in retransmission hash.
typedef enum op_xmit_transaction_e {
	OP_TRANS_TIMEOUT = 1,               // Transaction is timed out.
	OP_TRANS_RETRANSMIT = 2,            // Retransmit the message.
} op_xmit_transaction;

#ifdef EXTRA_CHECKS
void as_fabric_dump();
#endif

/*
**                                      Fabric Theory of Operation
**                                      ==========================
**
**   Overview:
**   ---------
**
**   The fabric is a "field of force", mediated by messages carried via TCP sockets, that binds a cluster
**   together.  The fabric must first be initialized by "as_fabric_init()", which creates the module-global
**   "g_fabric_args" object containing the parameters and data structures of the fabric.  After being
**   initialized, the fabric may be started up using "as_fabric_start()", which creates the worker threads
**   to send and receive messages and the accept thread to receive incoming connections.  (There is currently
**   no means to shut the fabric down.)
**
**   Fabric Message and Event Callbacks:
**   -----------------------------------
**
**   A module may register a callback function to process incoming fabric messages of a particular type using
**   "as_fabric_register_msg_fn()".  Message types are defined in "msg.h", and message handlers are registered
**   in the individual modules.  In addition, there is support for a single fabric heartbeat event handler
**   registered via "as_fabric_register_event_fn()", which is bound to the "as_paxos_event()" function of the
**   Paxos module.
**
**   Fabric Connection Setup:
**   ------------------------
**
**   When the local node sends a fabric message to a remote node, it will first try to open a new, non-blocking
**   TCP connection to the remote node using "fabric_connect()".  The number of permissible outbound connections
**   to a particular remote node is limited to being strictly lower than "FABRIC_MAX_FDS" (currently 8.)  Thus
**   a maximum of 7 outbound socket connections (each with its own FB [see below]), will generally be created to
**   each remote node as fabric messages are sent out.  Once the maximum number of outbound sockets is reached,
**   an already-existing connection will be re-used to send the message.  In addition, there will generally be
**   7 incoming connections (each with its own FB) from each remote node, for a total of 14 open sockets between
**   each pair of fabric nodes.
**
**   When a node opens a fabric connection to a remote node, the first fabric message sent will be used to
**   identify the local node by sending its 64-bit node ID (as the value of the "FS_FIELD_NODE" field) to the
**   remote node.  Correspondingly, when a new incoming connection is received via "fabric_accept_fn()", the
**   local node will determine the remote node's ID when processing the first fabric message received from the
**   remote node in "fabric_process_read_msg()".  Once the node ID has been determined, an FNE [see below] for
**   the remote node will be looked up in the FNE hash table (or else created and added to the table if not
**   found), and it will be associated with the incoming FB.  At this point, the incoming connection is set up,
**   and forthcoming messages will be parsed and dispatched to the appropriate message type handler callback
**   function.
**
**   Detailed Method of Fabric Node Connection / Disconnection:
**   ----------------------------------------------------------
**
**   For each remote node that is newly detected (either via receipt of a heartbeat or via the "weird" way
**   of first receiving an incoming fabric message from the remote node), a "fabric_node_element" (FNE) will
**   be constructed.  All known fabric nodes have a corresponding FNE in the "g_fabric_node_element_hash".
**   When a node is found to no longer be available (i.e., upon heartbeat receipt failure, which may be due
**   either to the remote node actually shutting down or else to a (potentially temporary) network outage),
**   the FNE will be destroyed.
**
**   Each active fabric connection is represented by a "fabric_buffer" (FB), with its own socket file descriptor
**   (FD), and which will be associated with an FNE.  There are two types ("polarities") of fabric connections,
**   outbound and inbound.  Outbound connections are created using "fabric_connect()" and all torn down using
**   "fabric_disconnect()".  Inbound connections are created in "fabric_accept_fn()".  Inbound connections are
**   shut down when the node departs the fabric and the remote endpoint is closed.
**
**   The FNE destruction procedure is handled in a lazy fashion via reference counts from the associated FBs.
**   In the normal case, a socket FD will be shut down cleanly, and the local node will receive an "epoll(4)"
**   event that allows the FB containing the FD to be released.  Once all of its FBs are released, the FNE
**   itself will be released.  In the abnormal case of a (possibly temporary) one-way network failure, the
**   fabric node has to be disconnected via "fabric_disconnect()", which will trigger FB cleanup via
**   cf_socket_shutdown(fb->sock) which will in turn trigger an epoll HUP event for each FB to be cleaned up.
**   Each FNE keeps a hash table of its connected outbound FBs for exactly this purpose of being able to clean
**   up when necessary.
**
**   Threading Structure:
**   --------------------
**
**   High-performance, concurrent fabric message exchange is provided via worker threads handling a particular
**   set of FBs.  (There is a default of 16, and a maximum of 128, fabric worker threads.)  Each worker thread
**   has an abstract Unix domain notification ("note") socket [Note:  This is a Linux-specific dependency!]
**   that is used to send events to the worker thread.  The main work of receiving and sending fabric messages
**   is handled by "fabric_worker_fn()", which does an "epoll_wait()" on the "note_fd" and all of the worker
**   thread's attached FBs.  Events on the "note_fd" are "NEW_FABRIC_BUFFER", received with a parameter that is
**   the FB containing the FD to be listened to or else shutdown.  Events on the FBs FDs may be either readable,
**   writable, or errors (which result in the particular fabric connection being closed.)
**
**   Object Management:
**   --------------------
**
**	 FNE and FB objects are reference counted. Correct book keeping on object references are vital to system
**	 operations.
**
**   Holders of FB references:
**     * fne->xmit_buffer_queue
**     * fne->outbound_fb_hash
**     * (worker_queue_element wqe).fb
**     * (epoll_event ev).data.ptr
**
**	 FBs are created in two methods: fabric_connect(), fabric_accept_fn()
**	 Both methods pass the newly created fb(ref=1) to wqe.fb(wqe.type=NEW_FABRIC_BUFFER). Some time later,
**	 NEW_FABRIC_BUFFER gets processed in fabric_worker_fn() and the reference gets passed to ev.data.ptr.
**
**   Holders of FNE references:
**     * fb->fne
**     * g_fabric_node_element_hash
**
**   cf_rc_release() on fb and fne objects must be done in conjuncture with it's removal from a holding source or
**   when done with an object obtained via rchash_get().
**
**   Debugging Utilities:
**   --------------------
**
**   The state of the fabric (all FNEs and FBs) can be logged using the "dump-fabric:" Info command.
*/

// #define DEBUG 1
// #define DEBUG_VERBOSE 1

typedef struct {
	// Arguably, these first two should be pushed into the msg system
	const msg_template 	*mt[M_TYPE_MAX];
	size_t 				mt_sz[M_TYPE_MAX];
	size_t 				scratch_sz[M_TYPE_MAX];

	as_fabric_msg_fn 	msg_cb[M_TYPE_MAX];
	void 				*msg_udata[M_TYPE_MAX];

	cf_queue    *msg_pool_queue[M_TYPE_MAX];   // A pool of unused messages, better than calling create

	int			num_workers;
	pthread_t	workers_th[MAX_FABRIC_WORKERS];
	cf_queue	*workers_queue[MAX_FABRIC_WORKERS]; // messages to workers - type worker_queue_element
	cf_poll		workers_poll[MAX_FABRIC_WORKERS]; // have workers export the epoll fd

	pthread_t	accept_th;

	char		note_sockname[108];
	int			note_server_fd;
	pthread_t	note_server_th;

	int			note_clients;
	int			note_fd[MAX_FABRIC_WORKERS];

	pthread_t   node_health_th;
} fabric_args;

// This hash:
// key is cf_node, value is a *pointer* to a fabric_node_element
rchash *g_fabric_node_element_hash;

#define FNE_QUEUE_LOW_PRI_SZ_LIMIT	50000

// A fabric_node_element is one-per-remote-endpoint
// it is stored in the fabric_node_element_hash, keyed by the node, so when a message_send
// is called we can find the queues, and it's linked from the fabric buffer which is
// attached to the file descriptor through the epoll args
//
// A fabric buffer sunk in an epoll holds a reference count on this object
typedef struct {
	cf_node 	node;	// when coming from a fd, we want to know the source node

	cf_atomic32 outbound_fd_counter;
	shash		*outbound_fb_hash;			// Key: fabric_buffer * ; Value: 0 (Arbitrary & unused.)
											// Holds references to fb(s) in the hash
	bool		live;						// set to false on shutdown

	uint64_t	good_write_counter;
	uint64_t	good_read_counter;

	pthread_mutex_t		outbound_idle_fb_queue_lock;
	cf_queue			outbound_idle_fb_queue;
	cf_queue_priority	*outbound_msg_queue;
} fabric_node_element;

#define FB_BUF_MEM_SZ		(1024 * 1024)

// When we get notification about a socket, this is the structure
// that's in the data portion
// Tells you everything about what's currently pending to read and write
// on this descriptor, so you can call read and write
typedef struct {
	cf_socket *sock;
	int worker_id;

	fabric_node_element *fne;

	bool is_outbound;
	bool failed;                    // This fb has failed and is unusable

	uint8_t		membuf[FB_BUF_MEM_SZ];

	// This is the write section.
	uint8_t		*w_buf;
	size_t		w_buf_sz;
	size_t		w_buf_written;
	msg			*w_msg_in_progress;
	size_t		w_count;

	// This is the read section.
	uint32_t	r_msg_size; 		// size of the incoming message
	msg_type	r_type;             // type of the incoming message
	uint8_t		*r_append;			// read from socket to here
	uint8_t		*r_parse;			// parse from here
	uint8_t		*r_end;				// the end of r_buf
	uint8_t 	*r_buf;				// may be r_stack_buf or allocated big buffer
} fabric_buffer;

// Worker queue
// Notification about various things, like a new file descriptor to manage
enum work_type {
	NEW_FABRIC_BUFFER,
};

typedef struct {
	enum work_type type;
	fabric_buffer *fb;
} worker_queue_element;

inline static void fne_release(fabric_node_element *fne);

static void fabric_worker_add(fabric_args *fa, fabric_buffer *fb);
static void fabric_buffer_set_epoll_state(fabric_buffer *fb);
static void fabric_heartbeat_event(int nevents, as_hb_event_node *events, void *udata);
static void fabric_buffer_release(fabric_buffer *fb);

// Ideally this would not be global, but there is in reality only one fabric,
// and the alternative would be to pass this value around everywhere.
static fabric_args *g_fabric_args = 0;

// The start message is always sent by the connecting device to specify
// what the remote endpoint's node ID is. We could pack other info
// in here as needed too
// The MsgType is used to specify the type, it's a good idea but not required
#define FS_FIELD_NODE 	 0
#define FS_ADDR          1
#define FS_PORT          2
#define FS_ANV           3
#define FS_ADDR_EX       4

// Special message at the front to describe my node ID
static msg_template fabric_mt[] = {
	{ FS_FIELD_NODE, M_FT_UINT64 },
	{ FS_ADDR, M_FT_UINT32 },
	{ FS_PORT, M_FT_UINT32 },
	{ FS_ANV, M_FT_BUF },
	{ FS_ADDR_EX, M_FT_BUF }
};

#define FS_MSG_SCRATCH_SIZE 512 // accommodate 64-node cluster

static fabric_node_element *
fne_create(cf_node node)
{
	fabric_node_element *fne = cf_rc_alloc(sizeof(fabric_node_element));

	if (! fne) {
		return NULL;
	}

	memset(fne, 0, sizeof(fabric_node_element));

	fne->node = node;
	fne->live = true;

	if (pthread_mutex_init(&fne->outbound_idle_fb_queue_lock, NULL) != 0) {
		cf_crash(AS_FABRIC, "failed to init xmit_buffer_queue_lock for fne %p", fne);
	}

	if (! cf_queue_init(&fne->outbound_idle_fb_queue, sizeof(fabric_buffer *), CF_QUEUE_ALLOCSZ, false)) {
		cf_crash(AS_FABRIC, "failed to create xmit_buffer_queue for fne %p", fne);
	}

	fne->outbound_msg_queue = cf_queue_priority_create(sizeof(msg *), true);

	if (! fne->outbound_msg_queue) {
		cf_crash(AS_FABRIC, "failed to create xmit_msg_queue for fne %p", fne);
	}

	if (shash_create(&(fne->outbound_fb_hash), ptr_hash_fn, sizeof(fabric_buffer *), sizeof(uint8_t), 100, SHASH_CR_MT_BIGLOCK) != SHASH_OK) {
		cf_crash(AS_FABRIC, "failed to create connected_fb_hash for fne %p", fne);
	}

	if (rchash_put_unique(g_fabric_node_element_hash, &node, sizeof(node), fne) != RCHASH_OK) {
		cf_info(AS_FABRIC, " received second notification of already extant node: %"PRIx64, node);
		fne_release(fne);
		return NULL;
	}

	cf_debug(AS_FABRIC, "create FNE: node %"PRIx64" fne %p", node, fne);

#ifdef EXTRA_CHECKS
	as_fabric_dump();
#endif

	return fne;
}

static void
fne_destructor(void *fne_o)
{
	fabric_node_element *fne = (fabric_node_element *)fne_o;
	cf_debug(AS_FABRIC, "destroy FNE: fne %p", fne);

	// xmit_buffer_queue section.
	if (cf_queue_sz(&fne->outbound_idle_fb_queue) != 0) {
		cf_crash(AS_FABRIC, "xmit_buffer_queue not empty as expected");
	}

	cf_queue_destroy(&fne->outbound_idle_fb_queue);
	pthread_mutex_destroy(&fne->outbound_idle_fb_queue_lock);

	// xmit_msg_queue section.
	while (true) {
		msg *m;

		if (cf_queue_priority_pop(fne->outbound_msg_queue, &m, CF_QUEUE_NOWAIT) != CF_QUEUE_OK) {
			cf_debug(AS_FABRIC, "fne_destructor(%p): xmit msg queue empty", fne);
			break;
		}

		cf_info(AS_FABRIC, "fabric node endpoint: destroy %"PRIx64" dropping message", fne->node);
		as_fabric_msg_put(m);
	}

	cf_queue_priority_destroy(fne->outbound_msg_queue);

	// connected_fb_hash section.
	if (shash_get_size(fne->outbound_fb_hash) != 0) {
		cf_crash(AS_FABRIC, "outbound_fb_hash not empty as expected");
	}

	shash_destroy(fne->outbound_fb_hash);
}

inline static void
fne_release(fabric_node_element *fne)
{
	if (0 == cf_rc_release(fne)) {
		fne_destructor(fne);
		cf_rc_free(fne);
	}
}

fabric_buffer *
fabric_buffer_create(cf_socket *sock)
{
	fabric_buffer *fb = cf_rc_alloc(sizeof(fabric_buffer));

	fb->sock = sock;
	fb->worker_id = -1; // no worker assigned yet
	fb->fne = NULL;
	fb->is_outbound = false;
	fb->failed = false;

	fb->w_count = 0;
	fb->w_buf = NULL;
	fb->w_msg_in_progress = NULL;

	fb->r_msg_size = 0;
	fb->r_type = M_TYPE_FABRIC; // since we don't have an "invalid"
	fb->r_buf = fb->membuf;
	fb->r_append = fb->r_buf;
	fb->r_parse = fb->r_buf;
	fb->r_end = fb->r_buf + FB_BUF_MEM_SZ;

	return fb;
}

static void
fabric_buffer_associate(fabric_buffer *fb, fabric_node_element *fne)
{
	cf_rc_reserve(fne);
	fb->fne = fne;
//	cf_debug(AS_FABRIC, "associate: fne %p to fb %p (fne ref now %d)",fne,fb,cf_rc_count(fne));
}

static void
fabric_buffer_disconnect(fabric_buffer *fb)
{
	fb->failed = true;

	if (! fb->is_outbound) {
		// inbound accepted connection. Does not requires a reference
		// release for the outbound fd hash.
		return;
	}

	if (shash_delete(fb->fne->outbound_fb_hash, &fb) != SHASH_OK) {
		cf_detail(AS_FABRIC, "fb %p is not in (fne %p)->outbound_fb_hash", fb, fb->fne);
		return;
	}

	cf_atomic32_decr(&fb->fne->outbound_fd_counter);
	cf_debug(AS_FABRIC, "removed fb %p from outbound_fb_hash", fb);
	cf_rc_release(fb);	// For delete from fne->outbound_fb_hash

	cf_socket_shutdown(fb->sock);
}

static void
fabric_buffer_release(fabric_buffer *fb)
{
	int cnt = cf_rc_release(fb);

	if (cnt < 0) {
		cf_crash(AS_FABRIC, "extra fabric_buffer_release %p", fb);
	}

	if (cnt == 0) {
		if (fb->w_msg_in_progress) {
			// First message (w_count == 0) is initial M_TYPE_FABRIC message and does not need to be saved.
			if (fb->fne && fb->w_count > 0) {
				cf_queue_priority_push(fb->fne->outbound_msg_queue, &fb->w_msg_in_progress, CF_QUEUE_PRIORITY_HIGH);
			}
			else {
				as_fabric_msg_put(fb->w_msg_in_progress);
			}
		}

		if (fb->fne) {
			fne_release(fb->fne);
			fb->fne = 0;
		}
		else {
			cf_debug(AS_FABRIC, "(releasing fb %p not attached to an FNE)", fb);
		}

		cf_socket_close(fb->sock);
		fb->sock = NULL;
		cf_atomic64_incr(&g_stats.fabric_connections_closed);

		// No longer assigned to a worker.
		fb->worker_id = -1;

		if (fb->r_buf != fb->membuf) {
			cf_free(fb->r_buf);
		}

		if (fb->w_buf && fb->w_buf != fb->membuf) {
			cf_free(fb->w_buf);
		}

		cf_rc_free(fb);
	}
}

static int
fabric_disconnect_reduce_fn(void *key, void *data, void *udata)
{
	fabric_buffer *fb = *(fabric_buffer **)key;

	if (! fb) {
		cf_crash(AS_FABRIC, "fb == NULL, don't pull NULLs into outbound_fb_hash");
	}

	if (fb->worker_id == -1) {
		cf_warning(AS_FABRIC, "fb %p has no worker_id", fb);
	}

	cf_socket_shutdown(fb->sock);
	fabric_buffer_release(fb);	// for delete from fne->connected_fb_hash

	return SHASH_REDUCE_DELETE;
}

// Disconnect a fabric node element and release its connected outbound fabric buffers.
int
fabric_disconnect(fabric_args *fa, fabric_node_element *fne)
{
	int num_fbs = shash_get_size(fne->outbound_fb_hash);
	int num_fds = cf_atomic32_get(fne->outbound_fd_counter);

	if (num_fbs > num_fds) {
		cf_warning(AS_FABRIC, "number of fabric buffers (%d) > number of open file descriptors (%d) for fne %p", num_fbs, num_fds, fne);
	}
	else if (num_fbs < num_fds) {
		cf_warning(AS_FABRIC, "number of fabric buffers (%d) < number of open file descriptors (%d) for fne %p", num_fbs, num_fds, fne);
	}

	shash_reduce_delete(fne->outbound_fb_hash, fabric_disconnect_reduce_fn, fa);

	return 0;
}

static void
fabric_buffer_set_keepalive_options(fabric_buffer *fb)
{
	if (g_config.fabric_keepalive_enabled) {
		cf_socket_keep_alive(fb->sock, g_config.fabric_keepalive_time, g_config.fabric_keepalive_intvl, g_config.fabric_keepalive_probes);
	}
}

// Create a connection to the remote node. This creates a non-blocking
// connection and adds it to the worker queue only, when the socket becomes
// writable, messages can start flowing.
static fabric_buffer *
fabric_connect(fabric_args *fa, fabric_node_element *fne)
{
	// Don't create too many conns because you'll just get small packets.
	uint32_t fds = cf_atomic32_incr(&(fne->outbound_fd_counter));
	if (fds >= FABRIC_MAX_FDS) {
		cf_atomic32_decr(&fne->outbound_fd_counter);
		return NULL;
	}

	// Get the ip address of the remote endpoint.
	cf_sock_addr addr;
	if (as_hb_getaddr(fne->node, &addr.addr) < 0) {
		cf_debug(AS_FABRIC, "fabric_connect: unknown remote endpoint %"PRIx64, fne->node);
		cf_atomic32_decr(&fne->outbound_fd_counter);
		return NULL;
	}

	// Get fabric port of the remote endpoint.
	cf_ip_port_from_node_id(fne->node, &addr.port);

	// Initiate the connect to the remote endpoint.
	cf_socket *sock;

	if (cf_socket_init_client_nb(&addr, &sock) < 0) {
		cf_debug(AS_FABRIC, "fabric connect could not create connect");
		cf_atomic32_decr(&fne->outbound_fd_counter);
		return NULL;
	}

	cf_atomic64_incr(&g_stats.fabric_connections_opened);

	// Create a fabric buffer to go along with the file descriptor.
	fabric_buffer *fb = fabric_buffer_create(sock);

	cf_socket_disable_nagle(fb->sock);
	fabric_buffer_set_keepalive_options(fb);
	fb->is_outbound = true;
	fabric_buffer_associate(fb, fne);

	// Grab a start message, send it to the remote endpoint so it knows me.
	msg *m = as_fabric_msg_get(M_TYPE_FABRIC);
	if (! m) {
		fabric_buffer_release(fb);
		cf_atomic32_decr(&fne->outbound_fd_counter);
		return NULL;
	}

	msg_set_uint64(m, FS_FIELD_NODE, g_config.self_node); // identifies self to remote

	fb->w_msg_in_progress = m;
	cf_rc_reserve(fb);	// for put into fne->outbound_fb_hash

	uint8_t value = 0;
	int rv = shash_put_unique(fne->outbound_fb_hash, &fb, &value);

	if (rv != SHASH_OK) {
		cf_crash(AS_FABRIC, "failed to add unique fb %p to fne %p outbound_fb_hash -- rv %d", fb, fne, rv);
	}

	return fb;
}

static void
fabric_buffer_send_progress(fabric_buffer *fb, bool is_last)
{
	uint8_t *send_buf;
	size_t send_sz;

	if (fb->w_buf) {
		// Partially sent msg.
		send_buf = fb->w_buf + fb->w_buf_written;
		send_sz = fb->w_buf_sz - fb->w_buf_written;
	}
	else {
		// Fresh msg.
		msg *m = fb->w_msg_in_progress;

		send_sz = msg_get_wire_size(m);

		if (send_sz > FB_BUF_MEM_SZ) {
			send_buf = (uint8_t *)cf_malloc(send_sz);
		}
		else {
			send_buf = fb->membuf;
		}

		fb->w_buf = send_buf;
		msg_fillbuf(m, send_buf, &send_sz);
		fb->w_buf_sz = send_sz;
		fb->w_buf_written = 0;
	}

	int32_t flags = MSG_NOSIGNAL | (is_last ? 0 : MSG_MORE);
	int32_t w_sz = cf_socket_send(fb->sock, send_buf, send_sz, flags);

	if (w_sz < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			fb->failed = true;
			cf_socket_write_shutdown(fb->sock);
			return;
		}

		w_sz = 0;	// treat as sending 0
	}
	else {
		fb->fne->good_write_counter = 0;
	}

	if ((size_t)w_sz == send_sz) {
		// Complete send.
		as_fabric_msg_put(fb->w_msg_in_progress);
		fb->w_msg_in_progress = NULL;

		if (fb->w_buf != fb->membuf) {
			cf_free(fb->w_buf);
		}

		fb->w_buf = NULL;
		fb->w_count++;
		cf_atomic64_incr(&g_stats.fabric_msgs_sent);
	}
	else {
		// Partial send.
		fb->w_buf_written += w_sz;
	}
}

static int
fabric_buffer_process_writable(fabric_buffer *fb)
{
	// Strategy with MSG_MORE to prevent small packets during migration.
	// Case 1 - socket buffer not full:
	//    Send all messages except last with MSG_MORE. Last message flushes
	//    buffer.
	// Case 2 - socket buffer full:
	//    All messages get sent with MSG_MORE but because buffer full, small
	//    packets still won't happen.
	fabric_node_element *fne = fb->fne;

	// Try first without extra locking.
	if (! fb->w_msg_in_progress) {
		cf_queue_priority_pop(fne->outbound_msg_queue, &fb->w_msg_in_progress, CF_QUEUE_NOWAIT);
	}

	while (fb->w_msg_in_progress) {
		msg *pending = NULL;

		cf_queue_priority_pop(fne->outbound_msg_queue, &pending, CF_QUEUE_NOWAIT);
		fabric_buffer_send_progress(fb, ! pending);

		if (fb->w_msg_in_progress) {
			if (pending) {
				// w_msg_inprogress not done so put it back.
				cf_queue_priority_push(fne->outbound_msg_queue, &pending, CF_QUEUE_PRIORITY_HIGH);
			}

			return 0;
		}

		fb->w_msg_in_progress = pending;
	}

	if (! fb->fne->live) {
		fabric_buffer_disconnect(fb);
	}
	else if (! fb->w_msg_in_progress) {
		// Try with bigger lock block to sync with as_fabric_send().
		pthread_mutex_lock(&fne->outbound_idle_fb_queue_lock);

		if (cf_queue_priority_pop(fne->outbound_msg_queue, &fb->w_msg_in_progress, CF_QUEUE_NOWAIT) == CF_QUEUE_EMPTY) {
			fabric_buffer_set_epoll_state(fb);
			cf_rc_reserve(fb);
			cf_queue_push(&fne->outbound_idle_fb_queue, &fb);
		}

		pthread_mutex_unlock(&fne->outbound_idle_fb_queue_lock);
	}

	return 0;
}

// Log information about existing "msg" objects and queues.
void
as_fabric_msg_queue_dump()
{
	cf_info(AS_FABRIC, "All currently-existing msg types:");
	int total_q_sz = 0;
	int total_alloced_msgs = 0;
	for (int i = 0; i < M_TYPE_MAX; i++) {
		int q_sz = cf_queue_sz(g_fabric_args->msg_pool_queue[i]);
		int num_of_type = cf_atomic_int_get(g_num_msgs_by_type[i]);
		total_alloced_msgs += num_of_type;
		if (q_sz || num_of_type) {
			cf_info(AS_FABRIC, "|msgq[%d]| = %d ; alloc'd = %d", i, q_sz, num_of_type);
			total_q_sz += q_sz;
		}
	}
	int num_msgs = cf_atomic_int_get(g_num_msgs);
	if (abs(num_msgs - total_alloced_msgs) > 2) {
		cf_warning(AS_FABRIC, "num msgs (%d) != total alloc'd msgs (%d)", num_msgs, total_alloced_msgs);
	}
	cf_info(AS_FABRIC, "Total num. msgs = %d ; Total num. queued = %d ; Delta = %d", num_msgs, total_q_sz, num_msgs - total_q_sz);
}

// Helper function. Pull a message off the internal queue.
msg *
as_fabric_msg_get(msg_type type)
{
	// What's coming in is actually a network value, so should be validated a bit.
	if (type >= M_TYPE_MAX) {
		return 0;
	}
	if (g_fabric_args->mt[type] == 0) {
		return 0;
	}

	msg *m = 0;
	cf_queue *q = g_fabric_args->msg_pool_queue[type];

	if (cf_queue_pop(q, &m, CF_QUEUE_NOWAIT) != 0) {
		msg_create(&m, type, g_fabric_args->mt[type],
				g_fabric_args->mt_sz[type], g_fabric_args->scratch_sz[type]);
	}
	else {
		msg_incr_ref(m);
	}

//	cf_debug(AS_FABRIC,"fabric_msg_get: m %p count %d",m,cf_rc_count(m));

	return m;
}

void
as_fabric_msg_put(msg *m)
{
	int cnt = cf_rc_release(m);

	if (cnt == 0) {
		msg_reset(m);

		if (cf_queue_sz(g_fabric_args->msg_pool_queue[m->type]) > 128) {
			msg_put(m);
		}
		else {
			cf_queue_push(g_fabric_args->msg_pool_queue[m->type], &m);
		}
	}
	else if (cnt < 0) {
		msg_dump(m, "extra put");
		cf_crash(AS_FABRIC, "extra put for msg type %d", m->type);
	}
}

static void
fabric_buffer_shift(fabric_buffer *fb, uint32_t parsable_size)
{
	if (fb->r_parse != fb->r_buf) {
		// Can overlap. (Though r_buf < r_parse, so memcpy() would work here.)
		memmove(fb->r_buf, fb->r_parse, parsable_size);
		fb->r_parse = fb->r_buf;
		fb->r_append = fb->r_parse + parsable_size;
	}
}

// Return true if we're done.
static bool
fabric_process_read_msg(fabric_buffer *fb)
{
	uint32_t parsable_size = (uint32_t)(fb->r_append - fb->r_parse);

	if (fb->r_msg_size == 0) {
		if (msg_get_initial(&fb->r_msg_size, &fb->r_type, fb->r_parse, parsable_size) != 0) {
			fabric_buffer_shift(fb, parsable_size);
			return true;
		}

		cf_detail(AS_FABRIC, "length required: %u", fb->r_msg_size);

		if (fb->r_msg_size > FB_BUF_MEM_SZ) {
			fb->r_buf = cf_malloc(fb->r_msg_size);
			fb->r_end = fb->r_buf + fb->r_msg_size;
			fabric_buffer_shift(fb, parsable_size);
			return true;
		}
	}

	// Return quick if we can't parse a full message.
	if (fb->r_msg_size > parsable_size) {
		fabric_buffer_shift(fb, parsable_size);
		return true;
	}

	if (! fb->fne) {
		// We have not yet associated this incoming connection with an endpoint,
		// so we need to read in the special fabric message that contains the
		// unique fabric address.
		msg *m = as_fabric_msg_get(M_TYPE_FABRIC);

		if (msg_parse(m, fb->r_parse, fb->r_msg_size) != 0) {
			cf_warning(AS_FABRIC, "fabric_process_read: msg_parse failed fabric msg");
			// TODO: Should never happen, because the first message in a connection should be short
			// abandon this connection is OK
			return true;
		}

		cf_node node;
		if (msg_get_uint64(m, FS_FIELD_NODE, &node) != 0) {
			// Node is is missing in first message. Should never
			// happen. Abandon this connection.
			return true;
		}

		as_fabric_msg_put(m);
		cf_debug(AS_FABRIC, "received and parse connection start message: from node %"PRIx64, node);

		// Have node, attach this read buffer to a fne.
		fabric_node_element *fne;

		if (rchash_get(g_fabric_node_element_hash, &node, sizeof(node), (void **)&fne) != RCHASH_OK) {
			// This happens sometimes. I might get a connection request before I get a ping
			// stating that anything exists. So make, then try again.
			fne = fne_create(node);
			cf_debug(AS_FABRIC, "created an FNE %p for node %"PRIx64" the weird way from incoming fabric msg!", fne, node);

			int rv = rchash_get(g_fabric_node_element_hash, &node, sizeof(node), (void **)&fne);

			if (rv != RCHASH_OK) {
				cf_crash(AS_FABRIC, "fabric_process_read_msg: cf_node unknown, can't create new endpoint descriptor odd %d", rv);
			}
		}

		fabric_buffer_associate(fb, fne);
		fne_release(fne);
	}
	else {
		// Standard path - parse into a regular message.
		msg *m = as_fabric_msg_get(fb->r_type);

		if (! m) {
			// this can happen if the TCP stream gets horribly out of sync
			// or if we're way out of memory --- close the connection and let
			// the error paths take care of it
			cf_warning(AS_FABRIC, "msg_parse could not parse message, for type %d", fb->r_type);
			cf_socket_write_shutdown(fb->sock);
			return true;
		}

		if (msg_parse(m, fb->r_parse, fb->r_msg_size) != 0) {
			cf_warning(AS_FABRIC, "msg_parse failed regular message, not supposed to happen: fb %p", fb);
			cf_socket_write_shutdown(fb->sock);
			return true;
		}

		// todo: have a full message, call the callback with the message

		cf_detail(AS_FABRIC, "msg_read: received msg: type %d node %"PRIx64, m->type, fb->fne->node);

		// statistic - received a message.
		cf_atomic64_incr(&g_stats.fabric_msgs_rcvd);
		// and it was a good read
		fb->fne->good_read_counter = 0;

		// deliver to registered guy
		if (g_fabric_args->msg_cb[m->type]) {
			(*g_fabric_args->msg_cb[m->type])(fb->fne->node, m, g_fabric_args->msg_udata[m->type]);
		}
		else {
			cf_warning(AS_FABRIC, "msg_read: could not deliver message type %d", m->type);
			as_fabric_msg_put(m);
		}
	}

	fb->r_parse += fb->r_msg_size;
	fb->r_msg_size = 0;

	if (fb->r_parse < fb->r_append) {
		// Not the last message.
		return false;
	}

	// If we used an allocated big buffer, we're done with it here - free it and
	// restore stack buffer mode.
	if (fb->r_buf != fb->membuf) {
		cf_free(fb->r_buf);
		fb->r_buf = fb->membuf;
		fb->r_end = fb->r_buf + FB_BUF_MEM_SZ;
	}

	fb->r_append = fb->r_buf;
	fb->r_parse = fb->r_buf;

	return true;
}

static int
fabric_process_readable(fabric_buffer *fb)
{
	int32_t	rsz = cf_socket_recv(fb->sock, fb->r_append, fb->r_end - fb->r_append, 0);

	if (rsz <= 0) {
		cf_debug(AS_FABRIC, "read returned %d, broken connection? %d %s", rsz, errno, cf_strerror(errno));
		return -1;
	}

	fb->r_append += rsz;

	while (! fabric_process_read_msg(fb)) {
		;
	}

	return 0;
}

// Sets the epoll mask for the related file descriptor according to what we
// need to do at the moment
// This is a little sketchy because we've got multiple threads hammering this, but
// it should be safe, maybe turning some of these into atomics would help
static void
fabric_buffer_set_epoll_state(fabric_buffer *fb)
{
	uint32_t events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

	if (fb->w_msg_in_progress) {
		events |= EPOLLOUT;
	}

	static int32_t err_ok[] = { ENOENT };
	CF_IGNORE_ERROR(cf_poll_modify_socket_forgiving(g_fabric_args->workers_poll[fb->worker_id],
			fb->sock, events, fb, sizeof(err_ok) / sizeof(int32_t), err_ok));
}

// Assign fb to a worker thread.
static void
fabric_worker_add(fabric_args *fa, fabric_buffer *fb)
{
	worker_queue_element e = {
			.type = NEW_FABRIC_BUFFER,
			.fb = fb
	};

	// Decide which worker to send to.
	// Put a message on that worker's queue send a byte to the worker over the notification FD.
	static int worker_add_index = 0;

	// Decide which queue to add to -- try round robin for the moment.
	int worker = worker_add_index++ % fa->num_workers;
	cf_debug(AS_FABRIC, "worker_fabric_add: adding fd %d to worker id %d notefd %d", CSFD(fb->sock), worker, fa->note_fd[worker]);

	fb->worker_id = worker;

	cf_queue_push(fa->workers_queue[worker], &e);

	// Write a byte to his file descriptor too.
	uint8_t note_byte = 1;
	cf_assert(fa->note_fd[worker], AS_FABRIC, CF_WARNING, "attempted write to fd 0");
	if (1 != send(fa->note_fd[worker], &note_byte, sizeof(note_byte), MSG_NOSIGNAL)) {
		// TODO!
		cf_info(AS_FABRIC, "can't write to notification file descriptor: will probably have to take down process");
	}
}

void *
fabric_worker_fn(void *argv)
{
	fabric_args *fa = (fabric_args *)argv;

	// Setup worker_id.
	pthread_t self = pthread_self();
	int worker_id;

	for (worker_id = 0; worker_id < MAX_FABRIC_WORKERS; worker_id++) {
		if (pthread_equal(fa->workers_th[worker_id], self) != 0) {
			break;
		}
	}

	if (worker_id == MAX_FABRIC_WORKERS) {
		cf_crash(AS_FABRIC, "thread setup failure");
	}

	cf_debug(AS_FABRIC, "fabric_worker_fn() created index %d", worker_id);

	// Setup epoll.
	cf_poll poll;
	cf_poll_create(&poll);
	fa->workers_poll[worker_id] = poll;

	// Setup note socket.
	struct sockaddr_un note_so;
	memset(&note_so, 0, sizeof(note_so));
	int note_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (note_fd < 0) {
		cf_debug(AS_FABRIC, "Could not create socket for notification thread");
		return 0;
	}
	note_so.sun_family = AF_UNIX;
	strcpy(note_so.sun_path, fa->note_sockname);
	int len = sizeof(note_so.sun_family) + strlen(note_so.sun_path) + 1;
	// Use an abstract Unix domain socket [Note:  Linux-specific!] by setting the first path character to NUL.
	note_so.sun_path[0] = '\0';
	if (connect(note_fd, (struct sockaddr *)&note_so, len) == -1) {
		cf_crash(AS_FABRIC, "could not connect to notification socket");
		return 0;
	}
	// Write the one byte that is my index.
	uint8_t fd_idx = worker_id;
	cf_assert(note_fd, AS_FABRIC, CF_WARNING, "attempted write to fd 0");
	if (1 != send(note_fd, &fd_idx, sizeof(fd_idx), MSG_NOSIGNAL)) {
		// TODO
		cf_debug(AS_FABRIC, "can't write to notification fd: probably need to blow up process errno %d", errno);
	}

	// File my notification information.
	cf_poll_add_socket(poll, WSFD(note_fd), EPOLLIN | EPOLLERR, &note_fd);

	while (true) {
		// We should never be canceled externally, but just in case.
		pthread_testcancel();

		cf_poll_event events[64];
		memset(events, 0, sizeof(events));
		int nevents = cf_poll_wait(poll, events, 64, -1);

		for (int i = 0; i < nevents; i++) {
			if (events[i].data == &note_fd) {
				if (events[i].events & EPOLLIN) {
					uint8_t note_byte;

					if (-1 == read(note_fd, &note_byte, sizeof(note_byte))) {
						// Suppress GCC warning for unused return value.
					}

					// Got some kind of notification - check my queue.
					worker_queue_element wqe;
					if (cf_queue_pop(fa->workers_queue[worker_id], &wqe, 0) == CF_QUEUE_OK) {
						if (wqe.type == NEW_FABRIC_BUFFER) {
							fabric_buffer *fb = wqe.fb;
							uint32_t events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

							if (fb->w_msg_in_progress) {
								events |= EPOLLOUT;
							}

							cf_poll_add_socket(poll, fb->sock, events, fb);
						}
						else {
							cf_warning(AS_FABRIC, "worker %d received unknown notification %d on queue", worker_id, wqe.type);
						}
					}
				}

				continue;
			}

			fabric_buffer *fb = events[i].data;
			cf_detail(AS_FABRIC, "epoll trigger: fd %d events %x", CSFD(fb->sock), events[i].events);

			if (fb->fne && (fb->fne->live == false)) {
				cf_poll_delete_socket(poll, fb->sock);
				fabric_buffer_disconnect(fb);
				fabric_buffer_release(fb);
				continue;
			}

			// Handle remote close, socket errors.
			// Also triggered by call to cf_socket_shutdown(fb->sock), but only first call.
			// Not triggered by cf_socket_close(fb->sock), which automatically EPOLL_CTL_DEL.
			if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				cf_debug(AS_FABRIC, "epoll : error, will close: fb %p fd %d errno %d", fb, CSFD(fb->sock), errno);
				cf_poll_delete_socket(poll, fb->sock);
				fabric_buffer_disconnect(fb);
				fabric_buffer_release(fb);
				continue;
			}

			if (events[i].events & EPOLLIN) {
				cf_detail(AS_FABRIC, "fabric_buffer_readable %p", fb);

				if (fabric_process_readable(fb) < 0) {
					cf_poll_delete_socket(poll, fb->sock);
					fabric_buffer_disconnect(fb);
					fabric_buffer_release(fb);
					continue;
				}
			}

			if (events[i].events & EPOLLOUT) {
				cf_detail(AS_FABRIC, "fabric_buffer_writable: %p", fb);

				if (fabric_buffer_process_writable(fb) < 0) {
					cf_poll_delete_socket(poll, fb->sock);
					fabric_buffer_disconnect(fb);
					fabric_buffer_release(fb);
					continue;
				}
			}
		}
	}

	return 0;
}

// Do the network accepts here, and allocate a file descriptor to an epoll
// worker thread.
static void *
fabric_accept_fn(void *argv)
{
	fabric_args *fa = (fabric_args *)argv;

	// Create listener socket.
	cf_socket_cfg sc;
	sc.addr = "0.0.0.0";     // inaddr any!
	sc.port = g_config.fabric_port;
	sc.reuse_addr = (g_config.socket_reuse_addr) ? true : false;
	sc.type = SOCK_STREAM;
	if (0 != cf_socket_init_server(&sc)) {
		cf_crash(AS_FABRIC, "Could not create fabric listener socket - check configuration");
	}

	cf_debug(AS_FABRIC, "fabric_accept: creating listener");

	while (true) {
		// Accept new connections on the service socket.
		cf_socket *csock;
		cf_sock_addr sa;

		if (cf_socket_accept(sc.sock, &csock, &sa) < 0) {
			if (errno == EMFILE) {
				cf_info(AS_FABRIC, "warning: low on file descriptors");
				continue;
			}
			else {
				cf_crash(AS_FABRIC, "cf_socket_accept: %d %s", errno, cf_strerror(errno));
			}
		}

		cf_debug(AS_FABRIC, "fabric_accept: accepting new sock %d", CSFD(csock));

		// Set the socket to nonblocking.
		cf_socket_disable_blocking(csock);
		cf_atomic64_incr(&g_stats.fabric_connections_opened);

		fabric_buffer *fb = fabric_buffer_create(csock);
		fabric_worker_add(fa, fb);
	}

	return 0;
}

// Accept connections to the notification function here.
static void *
fabric_note_server_fn(void *argv)
{
	fabric_args *fa = (fabric_args *)argv;

	while (true) {
		struct sockaddr_un addr;
		socklen_t addr_sz = sizeof(addr);
		int fd = accept(fa->note_server_fd, (struct sockaddr *)&addr, &addr_sz);

		if (fd == -1) {
			cf_debug(AS_FABRIC, "note_server: accept failed: fd %d addr_sz %d : %s", fa->note_server_fd, addr_sz, cf_strerror(errno));
			return 0;
		}

		// Wait for the single byte which tell me which index this is.
		uint8_t fd_idx;
		if (read(fd, &fd_idx, sizeof(fd_idx)) != (ssize_t)sizeof(fd_idx)) {
			cf_debug(AS_FABRIC, "note_server: could not read index of fd");
			close(fd);
			continue;
		}

		cf_socket_disable_blocking(WSFD(fd));
		cf_atomic64_incr(&g_stats.fabric_connections_opened);
		cf_debug(AS_FABRIC, "Notification server: received connect from index %d", fd_idx);

		// File this worker in the list.
		fa->note_fd[fd_idx] = fd;
		fa->note_clients++;
	}

	return 0;
}

int
as_fabric_get_node_lasttime(cf_node node, uint64_t *lasttime)
{
	// Look up the node's FNE.
	fabric_node_element *fne;
	if (RCHASH_OK != rchash_get(g_fabric_node_element_hash, &node, sizeof(node), (void **)&fne)) {
		return -1;
	}

	// Get the last time read.
	*lasttime = fne->good_read_counter;

	cf_debug(AS_FABRIC, "asking about node %"PRIx64" good read %u good write %u",
			 node, (uint)fne->good_read_counter, (uint)fne->good_write_counter);

	fne_release(fne);

	return 0;
}

// The node health function:
// Every N millisecond, it increases the 'good read counter' and 'good write counter'
// on each node element.
// Every read and write stamps those values back to 0. Thus, you can easily pick up
// a node and see how healthy it is, but only when you suspect trouble. With a capital T!
static int
fabric_node_health_reduce_fn(void *key, uint32_t keylen, void *data, void *udata)
{
	fabric_node_element *fne = (fabric_node_element *)data;
	uint32_t  incr = *(uint32_t *)udata;

	fne->good_write_counter += incr;
	fne->good_read_counter += incr;
	return 0;
}

#define FABRIC_HEALTH_INTERVAL 40   // ms

void *
fabric_node_health_fn(void *argv)
{
	while (true) {
		uint64_t start = cf_getms();

		usleep(FABRIC_HEALTH_INTERVAL * 1000);

		uint32_t ms = cf_getms() - start;

		rchash_reduce(g_fabric_node_element_hash, fabric_node_health_reduce_fn, &ms);
	}

	return 0;
}

static void
fabric_node_disconnect(cf_node node)
{
	fabric_node_element *fne;

	if (rchash_get(g_fabric_node_element_hash, &node, sizeof(node), (void **)&fne) != RCHASH_OK) {
		cf_warning(AS_FABRIC, "fabric disconnect node: node %"PRIx64" not connected, PROBLEM", node);
		return;
	}

	cf_info(AS_FABRIC, "fabric disconnecting node: %"PRIx64, node);
	fne->live = false;

	if (RCHASH_OK != rchash_delete(g_fabric_node_element_hash, &node, sizeof(node))) {
		cf_warning(AS_FABRIC, "fabric disconnecting FAIL rchash delete: node %"PRIx64, node);
	}

	while (true) {
		fabric_buffer *fb;

		pthread_mutex_lock(&fne->outbound_idle_fb_queue_lock);
		int rv = cf_queue_pop(&fne->outbound_idle_fb_queue, &fb, CF_QUEUE_NOWAIT);
		pthread_mutex_unlock(&fne->outbound_idle_fb_queue_lock);

		if (rv != CF_QUEUE_OK) {
			cf_debug(AS_FABRIC, "fabric_node_disconnect(%"PRIx64"): fne: %p : xmit buffer queue empty", node, fne);
			break;
		}

		fabric_buffer_release(fb);
	}

	while (true) {
		msg *m;

		if (cf_queue_priority_pop(fne->outbound_msg_queue, &m, CF_QUEUE_NOWAIT) != CF_QUEUE_OK) {
			cf_debug(AS_FABRIC, "fabric_node_disconnect(%"PRIx64"): fne: %p : xmit msg queue empty", node, fne);
			break;
		}

		cf_debug(AS_FABRIC, "fabric: dropping message to now-gone (heartbeat fail) node %"PRIx64, node);
		as_fabric_msg_put(m);
	}

	// Clean up all connected outgoing fabric buffers attached to this FNE.
	fabric_disconnect(g_fabric_args, fne);
	fne_release(fne);
}

// Function is called when a new node created or destroyed on the heartbeat system.
// This will insert a new element in the hashtable that keeps track of all TCP connections
static void
fabric_heartbeat_event(int nevents, as_hb_event_node *events, void *udata)
{
	if ((nevents < 1) || (nevents > g_config.paxos_max_cluster_size) || !events) {
		cf_warning(AS_FABRIC, "fabric: received event count of %d", nevents);
		return;
	}

	for (int i = 0; i < nevents; i++) {
		switch (events[i].evt) {
			case AS_HB_NODE_ARRIVE:	{
				fabric_node_element *fne;

				// Create corresponding fabric node element - add it to the hash table.
				if (RCHASH_OK != rchash_get(g_fabric_node_element_hash, &(events[i].nodeid), sizeof(cf_node), (void **)&fne)) {
					fne = fne_create(events[i].nodeid);
					cf_debug(AS_FABRIC, "fhe(): created an FNE %p for node %"PRIx64" from HB_NODE_ARRIVE", fne, events[i].nodeid);
				}
				else {
					cf_debug(AS_FABRIC, "fhe(): found an already-existing FNE %p for node %"PRIx64" from HB_NODE_ARRIVE", fne, events[i].nodeid);
					cf_debug(AS_FABRIC, "fhe(): need to let go of it ~~ before fne_release(%p) count:%d", fne, cf_rc_count(fne));
					fne_release(fne);
				}
				cf_info(AS_FABRIC, "fabric: node %"PRIx64" arrived", events[i].nodeid);
				break;
			}
			case AS_HB_NODE_DEPART:
				cf_info(AS_FABRIC, "fabric: node %"PRIx64" departed", events[i].nodeid);
				fabric_node_disconnect(events[i].nodeid);
				break;
			default:
				cf_warning(AS_FABRIC, "fabric: received unknown event type %d %"PRIx64"", i, events[i].nodeid);
				break;
		}
	}

#ifdef EXTRA_CHECKS
	as_fabric_dump();
#endif
}

int
as_fabric_register_msg_fn(msg_type type, const msg_template *mt, size_t mt_sz,
		size_t scratch_sz, as_fabric_msg_fn msg_cb, void *msg_udata)
{
	if (type >= M_TYPE_MAX) {
		return(-1);
	}
	g_fabric_args->mt[type] = mt;
	g_fabric_args->mt_sz[type] = mt_sz;
	g_fabric_args->scratch_sz[type] = scratch_sz;
	g_fabric_args->msg_cb[type] = msg_cb;
	g_fabric_args->msg_udata[type] = msg_udata;
	return 0;
}

// Print out all the known nodes, connections, queue states
static int
fabric_status_node_reduce_fn(void *key, uint32_t keylen, void *data, void *udata)
{
	fabric_node_element *fne = (fabric_node_element *)data;
	cf_node *keyd = (cf_node *)key;

	cf_info(AS_FABRIC, "fabric status: fne %p node %"PRIx64" refcount %d", fne, *(uint64_t *)keyd, cf_rc_count(fne));

	return 0;
}

void *
fabric_status_ticker_fn(void *i_hate_gcc)
{
	while (true) {
		cf_info(AS_FABRIC, "fabric status ticker: %d nodes", rchash_get_size(g_fabric_node_element_hash));
		rchash_reduce( g_fabric_node_element_hash, fabric_status_node_reduce_fn, 0);
		sleep(7);
	}

	return NULL;
}

static int as_fabric_transact_init(void);

int
as_fabric_init()
{
	fabric_args *fa = cf_malloc(sizeof(fabric_args));
	memset(fa, 0, sizeof(fabric_args));
	g_fabric_args = fa;

	fa->num_workers = g_config.n_fabric_workers;

	// Register my little fabric message type, so I can create 'em.
	as_fabric_register_msg_fn(M_TYPE_FABRIC, fabric_mt, sizeof(fabric_mt),
			FS_MSG_SCRATCH_SIZE, 0 /* arrival function!*/, 0);

	// Create the cf_node hash table.
	rchash_create(&g_fabric_node_element_hash, cf_nodeid_rchash_fn, fne_destructor,
			sizeof(cf_node), 64, RCHASH_CR_MT_MANYLOCK);

	// Create a global queue for the stashing of wayward messages for reuse.
	for (int i = 0; i < M_TYPE_MAX; i++) {
		fa->msg_pool_queue[i] = cf_queue_create(sizeof(msg *), true);
	}

	// Create a thread for monitoring the health of nodes.
	pthread_create(&(fa->node_health_th), 0, fabric_node_health_fn, 0);

	as_fabric_transact_init();

	return 0;
}

int
as_fabric_start()
{
	fabric_args *fa = g_fabric_args;

	// Create a unix domain socket that all workers can connect to, then be written to
	// in order to wakeup from epoll wait.
	// Create a listener for the notification socket.
	if ((fa->note_server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		cf_crash(AS_FABRIC, "could not create note server fd: %d %s", errno, cf_strerror(errno));
	}

	struct sockaddr_un ns_so;
	memset(&ns_so, 0, sizeof(ns_so));
	ns_so.sun_family = AF_UNIX;
	snprintf(&fa->note_sockname[0], sizeof(ns_so.sun_path), "@/tmp/wn-%d", getpid());
	strcpy(ns_so.sun_path, fa->note_sockname);
	int ns_so_len = sizeof(ns_so.sun_family) + strlen(ns_so.sun_path) + 1;
	// Use an abstract Unix domain socket [Note:  Linux-specific!] by setting the first path character to NUL.
	ns_so.sun_path[0] = '\0';

	if (bind(fa->note_server_fd, (struct sockaddr *)&ns_so, ns_so_len) < 0) {
		cf_crash(AS_FABRIC, "Could not bind note server name %s: %d %s", ns_so.sun_path, errno, cf_strerror(errno));
	}

	if (listen(fa->note_server_fd, 5) < 0) {
		cf_crash(AS_FABRIC, "listen: %s", cf_strerror(errno));
	}

	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);

	// Create thread for accepting and filling notification fds.
	if (pthread_create(&(fa->note_server_th), &thr_attr, fabric_note_server_fn, fa) != 0) {
		cf_crash(AS_FABRIC, "Failed to create fabric_note_server_fn() thread");
	}

	// Create a set of workers for data motion.
	for (int i = 0; i < fa->num_workers; i++) {
		if (! (fa->workers_queue[i] = cf_queue_create(sizeof(worker_queue_element), true))) {
			cf_crash(AS_FABRIC, "Failed to create queue %d/%d", i, fa->num_workers);
		}

		if (pthread_create(&(fa->workers_th[i]), &thr_attr, fabric_worker_fn, fa) != 0) {
			cf_crash(AS_FABRIC, "Failed to create fabric_worker_fn() thread %d/%d", i, fa->num_workers);
		}
	}

	// We want all workers to be available before starting the accept thread.
	for (int i = 0; i < fa->num_workers; i++) {
		while (fa->note_fd[i] == 0) {
			usleep(100 * 1000);
		}
	}

	// Create the Accept thread.
	if (pthread_create(&(fa->accept_th), &thr_attr, fabric_accept_fn, fa) != 0) {
		cf_crash(AS_FABRIC, "Could not create thread to receive heartbeat");
	}

	// Register a callback with the heartbeat mechanism.
	as_hb_register_listener(fabric_heartbeat_event, fa);

	return 0;
}

int
as_fabric_send(cf_node node, msg *m, int priority)
{
	if (g_fabric_args == 0) {
		cf_debug(AS_FABRIC, "fabric send without initialized fabric, BOO!");
		return AS_FABRIC_ERR_UNINITIALIZED;
	}

	cf_detail(AS_FABRIC, "fabric send: m %p to node %"PRIx64, m, node);

	// Short circuit for self!
	if (g_config.self_node == node) {
		if (g_fabric_args->msg_cb[m->type]) {
			(*g_fabric_args->msg_cb[m->type])(node, m, g_fabric_args->msg_udata[m->type]);
			return AS_FABRIC_SUCCESS;
		}

		cf_debug(AS_FABRIC, "msg: self send to unregistered type: %d", m->type);
		return AS_FABRIC_ERR_BAD_MSG;
	}

	fabric_node_element *fne;
	int rv = rchash_get(g_fabric_node_element_hash, &node, sizeof(node), (void **)&fne);

	if (rv != RCHASH_OK) {
		if (rv == RCHASH_ERR_NOTFOUND) {
			cf_debug(AS_FABRIC, "fabric send to unknown node %"PRIx64, node);
			return AS_FABRIC_ERR_NO_NODE;
		}

		return AS_FABRIC_ERR_UNKNOWN;
	}

	if (! fne->live) {
		fne_release(fne);	// rchash_get
		return AS_FABRIC_ERR_NO_NODE;
	}

	fabric_buffer *fb;

	while (true) {
		pthread_mutex_lock(&fne->outbound_idle_fb_queue_lock);
		rv = cf_queue_pop(&fne->outbound_idle_fb_queue, &fb, CF_QUEUE_NOWAIT);
		pthread_mutex_unlock(&fne->outbound_idle_fb_queue_lock);

		if (rv != CF_QUEUE_OK) {
			fb = NULL;
			break;
		}

		if (fb->sock == NULL || fb->failed) {
			cf_detail(AS_FABRIC, "releasing fb: %p with fne: %p and fd: %d (%s)", fb, fb->fne, CSFD(fb->sock), fb->failed ? "Failed" : "Missing");
			fabric_buffer_release(fb);
			continue;
		}

		break;
	}

	if (! fb) {
		if (priority == AS_FABRIC_PRIORITY_LOW && cf_queue_priority_sz(fne->outbound_msg_queue) > FNE_QUEUE_LOW_PRI_SZ_LIMIT) {
			fne_release(fne);	// rchash_get
			return AS_FABRIC_ERR_QUEUE_FULL;
		}

		if ((fb = fabric_connect(g_fabric_args, fne)) != NULL) {
			cf_queue_priority_push(fne->outbound_msg_queue, &m, priority);
			fabric_worker_add(g_fabric_args, fb);
		}
		else {
			// Sync with fabric_buffer_process_writable() to avoid non-empty
			// xmit_msg_queue with every fb being in xmit_buffer_queue.
			pthread_mutex_lock(&fne->outbound_idle_fb_queue_lock);

			cf_queue_pop(&fne->outbound_idle_fb_queue, &fb, CF_QUEUE_NOWAIT);

			if (! fb) {
				cf_queue_priority_push(fne->outbound_msg_queue, &m, priority);
			}

			pthread_mutex_unlock(&fne->outbound_idle_fb_queue_lock);

			if (fb) {
				// Wake up.
				fb->w_msg_in_progress = m;
				fabric_buffer_set_epoll_state(fb);
				fabric_buffer_release(fb);	// xmit_buffer_queue
			}
		}
	}
	else {
		// Wake up.
		fb->w_msg_in_progress = m;
		fabric_buffer_set_epoll_state(fb);
		fabric_buffer_release(fb);	// xmit_buffer_queue
	}

	fne_release(fne);	// rchash_get

	return AS_FABRIC_SUCCESS;
}

int
fabric_get_node_list_fn(void *key, uint32_t keylen, void *data, void *udata)
{
	as_node_list *nl = (as_node_list *)udata;
	if (nl->sz == nl->alloc_sz)	{
		return 0;
	}
	nl->nodes[nl->sz] = *(cf_node *)key;
//	cf_debug(AS_FABRIC,"nl_nodes %d : %"PRIx64,nl->sz,nl->nodes[nl->sz]);
	nl->sz++;
	return 0;
}

static rchash *g_fabric_transact_xmit_hash = 0;
static rchash *g_fabric_transact_recv_hash = 0;

typedef struct {
	uint64_t	tid;
	cf_node 	node;
} __attribute__ ((__packed__)) transact_recv_key;

uint32_t
fabric_tranact_xmit_hash_fn(void *value, uint32_t value_len)
{
	// Todo: the input is a transaction id which really is just used directly,
	// but is depends on the size and whether we've got "masking bits"
	if (value_len != sizeof(uint64_t)) {
		cf_warning(AS_FABRIC, "transact hash fn received wrong size");
		return 0;
	}

	return (uint32_t)(*(uint64_t *)value);
}

uint32_t
fabric_tranact_recv_hash_fn (void *value, uint32_t value_len)
{
	// Todo: the input is a transaction id which really is just used directly,
	// but is depends on the size and whether we've got "masking bits"
	if (value_len != sizeof(transact_recv_key)) {
		cf_warning(AS_FABRIC, "transact hash fn received wrong size");
		return(0);
	}
	transact_recv_key *trk = (transact_recv_key *)value;

	return (uint32_t)trk->tid;
}

static cf_atomic64 g_fabric_transact_tid = 0;

typedef struct {
	// allocated tid, without the 'code'
	uint64_t   			tid;
	cf_node 			node;
	msg *				m;
	pthread_mutex_t 	LOCK;

	uint64_t			deadline_ms;  // absolute time according to cf_getms of expiration
	uint64_t			retransmit_ms; // when we retransmit (absolute deadline)
	int 				retransmit_period; // next time

	as_fabric_transact_complete_fn cb;
	void *				udata;
} fabric_transact_xmit;

typedef struct {
	cf_ll_element ll_e;
	int op;
	uint64_t tid;
} ll_fabric_transact_xmit_element;

typedef struct {
	cf_node 	node; // where it came from
	uint64_t	tid;  // inbound tid
} fabric_transact_recv;

static inline int
tid_code_get(uint64_t tid)
{
	return tid >> 56;
}

static inline uint64_t
tid_code_set(uint64_t tid, int code)
{
	return tid | (((uint64_t) code) << 56);
}

static inline uint64_t
tid_code_clear(uint64_t tid)
{
	return tid & 0xffffffffffffff;
}

#define TRANSACT_CODE_REQUEST 1
#define TRANSACT_CODE_RESPONSE 2

// Given the requirement to signal exactly once, we we need to call the callback or
// free the message?
//
// NO -- but it's OK to check and make sure someone signaled before the destructor
// WHY - because you need to be able to call the destructor from anywhere
//
// rchash destructors always free the internals but not the thing itself: thus to
// release, always call the _release function below, don't call this directly
void
fabric_transact_xmit_destructor(void *object)
{
	fabric_transact_xmit *ft = object;
	as_fabric_msg_put(ft->m);
}

void
fabric_transact_xmit_release(fabric_transact_xmit *ft)
{
	if (0 == cf_rc_release(ft)) {
		fabric_transact_xmit_destructor(ft);
		cf_rc_free(ft);
	}
}

static void
fabric_transact_recv_destructor(void *object)
{
//	(fabric_transact_recv *)object;
}

void
fabric_transact_recv_release(fabric_transact_recv *ft)
{
	if (0 == cf_rc_release(ft)) {
		fabric_transact_recv_destructor(ft);
		cf_rc_free(ft);
	}
}

int
as_fabric_transact_reply(msg *m, void *transact_data)
{
	fabric_transact_recv *ftr = (fabric_transact_recv *)transact_data;

	// This is a response - overwrite tid with response code etc.
	uint64_t xmit_tid = tid_code_set(ftr->tid, TRANSACT_CODE_RESPONSE);
	msg_set_uint64(m, 0, xmit_tid);

	if (as_fabric_send(ftr->node, m, AS_FABRIC_PRIORITY_MEDIUM) != 0) {
		as_fabric_msg_put(m);
	}

	return 0;
}

void
as_fabric_transact_start(cf_node dest, msg *m, int timeout_ms, as_fabric_transact_complete_fn cb, void *udata)
{
	// Todo: could check it against the list of global message ids

	if (m->f[0].type != M_FT_UINT64) {
		// error
		cf_warning(AS_FABRIC, "as_fabric_transact: first field must be int64");
		(*cb)(0, udata, AS_FABRIC_ERR_UNKNOWN);
		return;
	}

	fabric_transact_xmit *ft = cf_rc_alloc(sizeof(fabric_transact_xmit));
	if (! ft) {
		cf_warning(AS_FABRIC, "as_fabric_transact: can't malloc");
		(*cb)(0, udata, AS_FABRIC_ERR_UNKNOWN);
		return;
	}

	ft->tid = cf_atomic64_incr(&g_fabric_transact_tid);
	ft->node = dest;
	ft->m = m;
	uint64_t now = cf_getms();
	pthread_mutex_init(&ft->LOCK, 0);
	ft->deadline_ms = now + timeout_ms;
	ft->retransmit_period = 10; // 10 ms start
	ft->retransmit_ms = now + ft->retransmit_period; // hard start at 10 milliseconds
	ft->cb = cb;
	ft->udata = udata;

	uint64_t xmit_tid = tid_code_set(ft->tid, TRANSACT_CODE_REQUEST);

	// Set message tid.
	msg_set_uint64(m, 0, xmit_tid);

	// Put will take the reference, need to keep one around for the send.
	cf_rc_reserve(ft);
	if (0 != rchash_put(g_fabric_transact_xmit_hash, &ft->tid, sizeof(ft->tid), ft)) {
		cf_warning(AS_FABRIC, "as_fabric_transact: can't put in hash");
		cf_rc_release(ft);
		fabric_transact_xmit_release(ft);
		return;
	}

	// Transmit the initial message.
	msg_incr_ref(m);
	int rv = as_fabric_send(ft->node, ft->m, AS_FABRIC_PRIORITY_MEDIUM);

	if (rv != 0) {
		// Need to release the ref I just took with the incr_ref.
		as_fabric_msg_put(m);

		if (rv == -2) {
			// No destination node: callback & remove from hash.
			;
		}
	}
	fabric_transact_xmit_release(ft);

	return;
}

static as_fabric_transact_recv_fn fabric_transact_recv_cb[M_TYPE_MAX] = { 0 };
static void *fabric_transact_recv_udata[M_TYPE_MAX] = { 0 };

// Received a message. Could be a response to an outgoing message,
// or a new incoming transaction message.
int
fabric_transact_msg_fn(cf_node node, msg *m, void *udata)
{
	// Could check type against max, but msg should have already done that on creation.

	// Received a message, make sure we have a registered callback.
	if (fabric_transact_recv_cb[m->type] == 0) {
		cf_warning(AS_FABRIC, "transact: received message for transact with bad type %d, internal error", m->type);
		as_fabric_msg_put(m); // return to pool unexamined
		return 0;
	}

	// Check to see that we have an outstanding request (only cb once!).
	uint64_t tid = 0;
	if (0 != msg_get_uint64(m, 0 /*field_id*/, &tid)) {
		cf_warning(AS_FABRIC, "transact: received message with no tid");
		as_fabric_msg_put(m);
		return 0;
	}

	int code = tid_code_get(tid);
	tid = tid_code_clear(tid);

	// If it's a response, check against what you sent.
	if (code == TRANSACT_CODE_RESPONSE) {
		// cf_info(AS_FABRIC, "transact: received response");

		fabric_transact_xmit *ft;
		int rv = rchash_get(g_fabric_transact_xmit_hash, &tid, sizeof(tid), (void **)&ft);
		if (rv != 0) {
			cf_warning(AS_FABRIC, "No fabric transmit structure in global hash for fabric transaction-id %"PRIu64"", tid);
			as_fabric_msg_put(m);
			return 0;
		}

		pthread_mutex_lock(&ft->LOCK);

		// Make sure we haven't notified some other way, then notify caller.
		if (ft->cb) {
			(*ft->cb) (m, ft->udata, AS_FABRIC_SUCCESS);
			ft->cb = 0;
		}

		pthread_mutex_unlock(&ft->LOCK);

		// Ok if this happens twice....
		rchash_delete(g_fabric_transact_xmit_hash, &tid, sizeof(tid));

		// This will often be the final release.
		fabric_transact_xmit_release(ft);
	}
	else if (code == TRANSACT_CODE_REQUEST) {
		fabric_transact_recv *ftr = cf_malloc(sizeof(fabric_transact_recv));

		ftr->tid = tid; // has already been cleared
		ftr->node = node;

		// Notify caller - they will likely respond inline.
		(*fabric_transact_recv_cb[m->type])(node, m, ftr, fabric_transact_recv_udata[m->type]);
		cf_free(ftr);
	}
	else {
		cf_warning(AS_FABRIC, "transact: bad code on incoming message: %d", code);
		as_fabric_msg_put(m);
	}

	return 0;
}

// registers all of this message type as a
// transaction type message, which means the main message
int
as_fabric_transact_register(msg_type type, const msg_template *mt, size_t mt_sz,
		size_t scratch_sz, as_fabric_transact_recv_fn cb, void *udata)
{
	// Put details in the global structure.
	fabric_transact_recv_cb[type] = cb;
	fabric_transact_recv_udata[type] = udata;

	// Register my internal callback with the main message callback.
	as_fabric_register_msg_fn(type, mt, mt_sz, scratch_sz, fabric_transact_msg_fn, 0);

	return 0;
}

// Transaction maintenance threads
// this thread watches the hash table, and finds transactions that
// have completed and need to be signaled
static pthread_t g_fabric_transact_th;

static int
fabric_transact_xmit_reduce_fn(void *key, uint32_t keylen, void *o, void *udata)
{
	fabric_transact_xmit *ftx = (fabric_transact_xmit *)o;
	int op = 0;

	cf_detail(AS_FABRIC, "transact: xmit reduce");

	uint64_t now = cf_getms();

	pthread_mutex_lock(&ftx->LOCK);

	if (now > ftx->deadline_ms) {
		// Expire and remove transactions that are timed out.
		// Need to call application: we've timed out.
		op = OP_TRANS_TIMEOUT;
	}
	else if (now > ftx->retransmit_ms) {
		// retransmit, update time counters, etc
		ftx->retransmit_ms = now + ftx->retransmit_period;
		ftx->retransmit_period *= 2;
		op = OP_TRANS_RETRANSMIT;
	}

	if (op > 0) {
		// Add the transaction in linked list of transactions to be processed.
		// Process such transactions outside retransmit hash lock.
		// Why ?
		// Fabric short circuit the message to self.
		// It short circuits it by directly calling receiver function of corresponding module.
		// Receiver of module construct "reply" and hand over to fabric to deliver.
		// On receiving "reply", fabric removes original message, for which this is a reply, from retransmit hash
		//
		// "fabric_transact_xmit_reduce_fn" function is invoked by reduce_delete.
		// reduce_delete holds the lock over corrsponding hash (here "retransmit hash").
		// If the message, sent by this function, is short circuited by fabric,
		// the same thread will again try to get lock over "retransmit hash".
		// It is self dead lock.
		//
		// To avoid this process it outside retransmit hash lock.

		cf_ll *ll_fabric_transact_xmit  = (cf_ll *)udata;

		// Create new node for list.
		ll_fabric_transact_xmit_element *ll_ftx_ele = (ll_fabric_transact_xmit_element *)cf_malloc(sizeof(ll_fabric_transact_xmit_element));
		ll_ftx_ele->tid = ftx->tid;
		ll_ftx_ele->op = op;
		// Append into list.
		cf_ll_append(ll_fabric_transact_xmit, (cf_ll_element *)ll_ftx_ele);
	}
	pthread_mutex_unlock(&ftx->LOCK);
	return 0;
}

int
ll_ftx_reduce_fn(cf_ll_element *le, void *udata)
{
	ll_fabric_transact_xmit_element *ll_ftx_ele = (ll_fabric_transact_xmit_element *)le;

	fabric_transact_xmit *ftx;
	uint64_t tid;
	int rv;

	msg *m = 0;
	cf_node node;

	tid = ll_ftx_ele->tid;
	// rchash_get increment ref count on transaction ftx.
	rv = rchash_get(g_fabric_transact_xmit_hash, &tid, sizeof(tid), (void **)&ftx);
	if (rv != 0) {
		cf_warning(AS_FABRIC, "No fabric transmit structure in global hash for fabric transaction-id %"PRIu64"", tid);
		return (CF_LL_REDUCE_DELETE);
	}

	if (ll_ftx_ele->op == OP_TRANS_TIMEOUT) {

		// Call application: we've timed out.
		if (ftx->cb) {
			(*ftx->cb) ( 0, ftx->udata, AS_FABRIC_ERR_TIMEOUT);
			ftx->cb = 0;
		}
		cf_debug(AS_FABRIC, "fabric transact: %"PRIu64" timed out", tid);
		// rchash_delete removes ftx from hash and decrement ref count on it.
		rchash_delete(g_fabric_transact_xmit_hash, &tid, sizeof(tid));
		// It should be final release of transaction ftx.
		// On final release, it also decrements message ref count, taken by initial fabric_send.
		fabric_transact_xmit_release(ftx);
	}
	else if (ll_ftx_ele->op == OP_TRANS_RETRANSMIT) {
		//msg_incr_ref(ftx->m);
		if (ftx->m) {
			msg_incr_ref(ftx->m);
			m = ftx->m;
			node = ftx->node;
			if (0 != as_fabric_send(node, m, AS_FABRIC_PRIORITY_MEDIUM)) {
				cf_debug(AS_FABRIC, "fabric: transact: %"PRIu64" retransmit send failed", tid);
				as_fabric_msg_put(m);
			}
			else {
				cf_debug(AS_FABRIC, "fabric: transact: %"PRIu64" retransmit send success", tid);
			}
		}
		// Decrement ref count, incremented by rchash_get.
		fabric_transact_xmit_release(ftx);
	}
	// Remove it from link list.
	return CF_LL_REDUCE_DELETE;
}

// Function to delete node in linked list
static void
ll_ftx_destructor_fn(cf_ll_element *e)
{
	cf_free(e);
}

// long running thread for tranaction maintance
void *
fabric_transact_fn(void *argv)
{
	// Create a list of transactions to be processed in each pass.
	cf_ll ll_fabric_transact_xmit;
	// Initialize list to empty list.
	// This list is processed by single thread. No need of a lock.
	cf_ll_init(&ll_fabric_transact_xmit, &ll_ftx_destructor_fn, false);
	while (true) {
		usleep(10000); // 10 ms for now

		// Visit each entry in g_fabric_transact_xmit_hash and select entries to be retransmitted or timed out.
		// Add that transaction id (tid) in the link list 'll_fabric_transact_xmit'.
		rchash_reduce(g_fabric_transact_xmit_hash, fabric_transact_xmit_reduce_fn, (void *)&ll_fabric_transact_xmit);

		if (cf_ll_size(&ll_fabric_transact_xmit)) {
			// There are transactions to be processed.
			// Process each transaction in list.
			cf_ll_reduce(&ll_fabric_transact_xmit, true /*forward*/, ll_ftx_reduce_fn, NULL);
		}
	}

	return 0;
}

static int
as_fabric_transact_init()
{
	// Create the transaction hash table.
	rchash_create(&g_fabric_transact_xmit_hash, fabric_tranact_xmit_hash_fn , fabric_transact_xmit_destructor,
				   sizeof(uint64_t), 64 /* n_buckets */, RCHASH_CR_MT_MANYLOCK);

	rchash_create(&g_fabric_transact_recv_hash, fabric_tranact_recv_hash_fn , fabric_transact_recv_destructor,
				   sizeof(uint64_t), 64 /* n_buckets */, RCHASH_CR_MT_MANYLOCK);

	// Create a thread for monitoring transactions.
	pthread_create(&g_fabric_transact_th, 0, fabric_transact_fn, 0);

	return 0;
}

// To send to all nodes, simply set the nodes pointer to 0 (and we'll just fetch
// the list internally)
// If an element in the array is 0, then there's no destination
int
as_fabric_send_list(cf_node *nodes, int nodes_sz, msg *m, int priority)
{
	as_node_list nl;
	if (nodes == 0) {
		as_fabric_get_node_list(&nl);
		nodes = &nl.nodes[0];
		nodes_sz = nl.sz;
	}

	if (nodes_sz == 1) {
		return as_fabric_send(nodes[0], m, priority);
	}

	cf_debug(AS_FABRIC, "as_fabric_send_list sending: m %p", m);
	for (int j = 0; j < nodes_sz; j++) {
		cf_debug(AS_FABRIC, "  destination: %"PRIx64"\n", nodes[j]);
	}

	// Careful with the ref count here: need to increment before every
	// send except the last.
	int rv = 0;
	int index;
	for (index = 0; index < nodes_sz; index++) {
		if (index != nodes_sz - 1) {
			msg_incr_ref(m);
		}
		rv = as_fabric_send(nodes[index], m, priority);
		if (0 != rv) {
			goto Cleanup;
		}
	}

	return 0;

Cleanup:
	if (index != nodes_sz - 1) {
		as_fabric_msg_put(m);
	}

	return rv;
}

void
as_fabric_dump(bool verbose)
{
	as_node_list nl;
	as_fabric_get_node_list(&nl);

	cf_info(AS_FABRIC, " Fabric Dump: %d nodes known", nl.sz);
	for (uint i = 0; i < nl.sz; i++) {
		if (nl.nodes[i] == g_config.self_node) {
			cf_info(AS_FABRIC, "    %"PRIx64" node is self", nl.nodes[i]);
			continue;
		}

		fabric_node_element *fne;
		int rv = rchash_get(g_fabric_node_element_hash, &nl.nodes[i], sizeof(cf_node), (void **)&fne);

		if (rv != RCHASH_OK) {
			cf_info(AS_FABRIC, "   %"PRIx64" node not found in hash although reported available", nl.nodes[i]);
		}
		else {
			cf_info(AS_FABRIC, "    %"PRIx64" fds %d live %d goodwrite %"PRIu64" goodread %"PRIu64" q %d", fne->node,
					fne->outbound_fd_counter, fne->live, fne->good_write_counter, fne->good_read_counter, cf_queue_priority_sz(fne->outbound_msg_queue));
			fne_release(fne);
		}
	}
}
