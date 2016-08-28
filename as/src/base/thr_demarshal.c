/*
 * thr_demarshal.c
 *
 * Copyright (C) 2008-2014 Aerospike, Inc.
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

#include "base/thr_demarshal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/param.h>	// for MIN()
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_queue.h"

#include "fault.h"
#include "jem.h"
#include "hist.h"
#include "socket.h"

#include "base/as_stap.h"
#include "base/batch.h"
#include "base/cfg.h"
#include "base/packet_compression.h"
#include "base/proto.h"
#include "base/security.h"
#include "base/stats.h"
#include "base/thr_info.h"
#include "base/thr_tsvc.h"
#include "base/transaction.h"
#include "base/xdr_serverside.h"

#ifdef USE_JEM
#include "base/datamodel.h"
#endif

#define POLL_SZ 1024

#define XDR_WRITE_BUFFER_SIZE (5 * 1024 * 1024)
#define XDR_READ_BUFFER_SIZE (15 * 1024 * 1024)

extern void *thr_demarshal(void *arg);

typedef struct {
	cf_poll			polls[MAX_DEMARSHAL_THREADS];
	unsigned int	num_threads;
	pthread_t	dm_th[MAX_DEMARSHAL_THREADS];
} demarshal_args;

static demarshal_args *g_demarshal_args = 0;


//
// File handle reaper.
//

pthread_mutex_t	g_file_handle_a_LOCK = PTHREAD_MUTEX_INITIALIZER;
as_file_handle	**g_file_handle_a = 0;
uint			g_file_handle_a_sz;
pthread_t		g_demarshal_reaper_th;

void *thr_demarshal_reaper_fn(void *arg);
static cf_queue *g_freeslot = 0;

void
thr_demarshal_pause(as_file_handle *fd_h)
{
	fd_h->trans_active = true;
}

void
thr_demarshal_resume(as_file_handle *fd_h)
{
	fd_h->trans_active = false;

	// Make the demarshal thread aware of pending connection data (if any).
	// Writing to an FD's event mask makes the epoll instance re-check for
	// data, even when edge-triggered. If there is data, the demarshal thread
	// gets EPOLLIN for this FD.

	// This causes ENOENT, when we reached NextEvent_FD_Cleanup (e.g, because
	// the client disconnected) while the transaction was still ongoing.

	static int32_t err_ok[] = { ENOENT };
	CF_IGNORE_ERROR(cf_poll_modify_socket_forgiving(fd_h->poll, fd_h->sock,
			EPOLLIN | EPOLLET | EPOLLRDHUP, fd_h,
			sizeof(err_ok) / sizeof(int32_t), err_ok));
}

void
demarshal_file_handle_init()
{
	struct rlimit rl;

	pthread_mutex_lock(&g_file_handle_a_LOCK);

	if (g_file_handle_a == 0) {
		if (-1 == getrlimit(RLIMIT_NOFILE, &rl)) {
			cf_crash(AS_DEMARSHAL, "getrlimit: %s", cf_strerror(errno));
		}

		// Initialize the message pointer array and the unread byte counters.
		g_file_handle_a = cf_calloc(rl.rlim_cur, sizeof(as_proto *));
		cf_assert(g_file_handle_a, AS_DEMARSHAL, CF_CRITICAL, "allocation: %s", cf_strerror(errno));
		g_file_handle_a_sz = rl.rlim_cur;

		for (int i = 0; i < g_file_handle_a_sz; i++) {
			cf_queue_push(g_freeslot, &i);
		}

		pthread_create(&g_demarshal_reaper_th, 0, thr_demarshal_reaper_fn, 0);

		// If config value is 0, set a maximum proto size based on the RLIMIT.
		if (g_config.n_proto_fd_max == 0) {
			g_config.n_proto_fd_max = rl.rlim_cur / 2;
			cf_info(AS_DEMARSHAL, "setting default client file descriptors to %d", g_config.n_proto_fd_max);
		}
	}

	pthread_mutex_unlock(&g_file_handle_a_LOCK);
}

// Keep track of the connections, since they're precious. Kill anything that
// hasn't been used in a while. The file handle array keeps a reference count,
// and allows a reaper to run through and find the ones to reap. The table is
// only written by the demarshal threads, and only read by the reaper thread.
void *
thr_demarshal_reaper_fn(void *arg)
{
	uint64_t last = cf_getms();

	while (true) {
		uint64_t now = cf_getms();
		uint inuse_cnt = 0;
		uint64_t kill_ms = g_config.proto_fd_idle_ms;
		bool refresh = false;

		if (now - last > (uint64_t)(g_config.sec_cfg.privilege_refresh_period * 1000)) {
			refresh = true;
			last = now;
		}

		pthread_mutex_lock(&g_file_handle_a_LOCK);

		for (int i = 0; i < g_file_handle_a_sz; i++) {
			if (g_file_handle_a[i]) {
				as_file_handle *fd_h = g_file_handle_a[i];

				if (refresh) {
					as_security_refresh(fd_h);
				}

				// Reap, if asked to.
				if (fd_h->reap_me) {
					cf_debug(AS_DEMARSHAL, "Reaping FD %d as requested", CSFD(fd_h->sock));
					g_file_handle_a[i] = 0;
					cf_queue_push(g_freeslot, &i);
					as_release_file_handle(fd_h);
					fd_h = 0;
				}
				// Reap if past kill time.
				else if ((0 != kill_ms) && (fd_h->last_used + kill_ms < now)) {
					if (fd_h->fh_info & FH_INFO_DONOT_REAP) {
						cf_debug(AS_DEMARSHAL, "Not reaping the fd %d as it has the protection bit set", CSFD(fd_h->sock));
						inuse_cnt++;
						continue;
					}

					cf_socket_shutdown(fd_h->sock); // will trigger epoll errors
					cf_debug(AS_DEMARSHAL, "remove unused connection, fd %d", CSFD(fd_h->sock));
					g_file_handle_a[i] = 0;
					cf_queue_push(g_freeslot, &i);
					as_release_file_handle(fd_h);
					fd_h = 0;
					g_stats.reaper_count++;
				}
				else {
					inuse_cnt++;
				}
			}
		}

		pthread_mutex_unlock(&g_file_handle_a_LOCK);

		if ((g_file_handle_a_sz / 10) > (g_file_handle_a_sz - inuse_cnt)) {
			cf_warning(AS_DEMARSHAL, "less than ten percent file handles remaining: %d max %d inuse",
					g_file_handle_a_sz, inuse_cnt);
		}

		// Validate the system statistics.
		if (g_stats.proto_connections_opened - g_stats.proto_connections_closed != inuse_cnt) {
			cf_debug(AS_DEMARSHAL, "reaper: mismatched connection count:  %"PRIu64" in stats vs %d calculated",
					g_stats.proto_connections_opened - g_stats.proto_connections_closed,
					inuse_cnt);
		}

		sleep(1);
	}

	return NULL;
}

int
thr_demarshal_read_file(const char *path, char *buffer, size_t size)
{
	int res = -1;
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		cf_warning(AS_DEMARSHAL, "Failed to open %s for reading.", path);
		goto cleanup0;
	}

	size_t len = 0;

	while (len < size - 1) {
		ssize_t n = read(fd, buffer + len, size - len - 1);

		if (n < 0) {
			cf_warning(AS_DEMARSHAL, "Failed to read from %s", path);
			goto cleanup1;
		}

		if (n == 0) {
			buffer[len] = 0;
			res = 0;
			goto cleanup1;
		}

		len += n;
	}

	cf_warning(AS_DEMARSHAL, "%s is too large.", path);

cleanup1:
	close(fd);

cleanup0:
	return res;
}

int
thr_demarshal_read_integer(const char *path, int *value)
{
	char buffer[21];

	if (thr_demarshal_read_file(path, buffer, sizeof(buffer)) < 0) {
		return -1;
	}

	char *end;
	uint64_t x = strtoul(buffer, &end, 10);

	if (*end != '\n' || x > INT_MAX) {
		cf_warning(AS_DEMARSHAL, "Invalid integer value in %s.", path);
		return -1;
	}

	*value = (int)x;
	return 0;
}

typedef enum {
	BUFFER_TYPE_SEND,
	BUFFER_TYPE_RECEIVE
} buffer_type;

int
thr_demarshal_set_buffer(cf_socket *sock, buffer_type type, int size)
{
	static int rcv_max = -1;
	static int snd_max = -1;

	const char *proc;
	int *max;

	switch (type) {
	case BUFFER_TYPE_RECEIVE:
		proc = "/proc/sys/net/core/rmem_max";
		max = &rcv_max;
		break;

	case BUFFER_TYPE_SEND:
		proc = "/proc/sys/net/core/wmem_max";
		max = &snd_max;
		break;

	default:
		cf_crash(AS_DEMARSHAL, "Invalid buffer type: %d", (int32_t)type);
		return -1; // cf_crash() should have a "noreturn" attribute, but is a macro
	}

	int tmp = ck_pr_load_int(max);

	if (tmp < 0) {
		if (thr_demarshal_read_integer(proc, &tmp) < 0) {
			cf_warning(AS_DEMARSHAL, "Failed to read %s; should be at least %d. Please verify.", proc, size);
			tmp = size;
		}
	}

	if (tmp < size) {
		cf_warning(AS_DEMARSHAL, "Buffer limit is %d, should be at least %d. Please set %s accordingly.",
				tmp, size, proc);
		return -1;
	}

	ck_pr_cas_int(max, -1, tmp);

	switch (type) {
	case BUFFER_TYPE_RECEIVE:
		cf_socket_set_receive_buffer(sock, size);
		break;

	case BUFFER_TYPE_SEND:
		cf_socket_set_send_buffer(sock, size);
		break;
	}

	return 0;
}

int
thr_demarshal_config_xdr(cf_socket *sock)
{
	if (thr_demarshal_set_buffer(sock, BUFFER_TYPE_RECEIVE, XDR_READ_BUFFER_SIZE) < 0) {
		return -1;
	}

	if (thr_demarshal_set_buffer(sock, BUFFER_TYPE_SEND, XDR_WRITE_BUFFER_SIZE) < 0) {
		return -1;
	}

	cf_socket_set_window(sock, XDR_READ_BUFFER_SIZE);
	cf_socket_enable_nagle(sock);
	return 0;
}

// Log information about a suspicious incoming transaction.
static void
log_as_proto_and_peeked_data(as_proto *proto, uint8_t *peekbuf, size_t peeked_data_sz)
{
	cf_warning(AS_DEMARSHAL, "as_proto {version = %d ; type = %d ; sz =  %"PRIu64" (0x%"PRIx64")}", proto->version, proto->type, (uint64_t)proto->sz, (uint64_t)proto->sz);
	cf_warning(AS_DEMARSHAL, "peeked_data_sz = %ld (0x%zx)", peeked_data_sz, peeked_data_sz);
	cf_warning_binary(AS_DEMARSHAL, peekbuf, peeked_data_sz, CF_DISPLAY_HEX_SPACED, "peekbuf");
}

// Set of threads which talk to client over the connection for doing the needful
// processing. Note that once fd is assigned to a thread all the work on that fd
// is done by that thread. Fair fd usage is expected of the client. First thread
// is special - also does accept [listens for new connections]. It is the only
// thread which does it.
void *
thr_demarshal(void *arg)
{
	cf_socket_cfg *s, *ls, *xs;
	cf_poll poll;
	int nevents, i, n;
	cf_clock last_fd_print = 0;

#if defined(USE_SYSTEMTAP)
	uint64_t nodeid = g_config.self_node;
#endif

	// Early stage aborts; these will cause faults in process scope.
	cf_assert(arg, AS_DEMARSHAL, CF_CRITICAL, "invalid argument");
	s = &g_config.socket;
	ls = &g_config.localhost_socket;
	xs = &g_config.xdr_socket;

#ifdef USE_JEM
	int orig_arena;
	if (0 > (orig_arena = jem_get_arena())) {
		cf_crash(AS_DEMARSHAL, "Failed to get original arena for thr_demarshal()!");
	} else {
		cf_info(AS_DEMARSHAL, "Saved original JEMalloc arena #%d for thr_demarshal()", orig_arena);
	}
#endif

	// Figure out my thread index.
	pthread_t self = pthread_self();
	int thr_id;
	for (thr_id = 0; thr_id < MAX_DEMARSHAL_THREADS; thr_id++) {
		if (0 != pthread_equal(g_demarshal_args->dm_th[thr_id], self))
			break;
	}

	if (thr_id == MAX_DEMARSHAL_THREADS) {
		cf_debug(AS_FABRIC, "Demarshal thread could not figure own ID, bogus, exit, fu!");
		return(0);
	}

	cf_poll_create(&poll);

	// First thread accepts new connection at interface socket.
	if (thr_id == 0) {
		demarshal_file_handle_init();

		cf_poll_add_socket(poll, s->sock, EPOLLIN | EPOLLERR | EPOLLHUP, &s->sock);
		cf_info(AS_DEMARSHAL, "Service started: socket %s:%d", s->addr, s->port);

		if (ls->sock) {
			cf_poll_add_socket(poll, ls->sock, EPOLLIN | EPOLLERR | EPOLLHUP, &ls->sock);
			cf_info(AS_DEMARSHAL, "Service also listening on localhost socket %s:%d", ls->addr, ls->port);
		}

		if (xs->sock) {
			cf_poll_add_socket(poll, xs->sock, EPOLLIN | EPOLLERR | EPOLLHUP, &xs->sock);
			cf_info(AS_DEMARSHAL, "Service also listening on XDR info socket %s:%d", xs->addr, xs->port);
		}
	}

	g_demarshal_args->polls[thr_id] = poll;
	cf_detail(AS_DEMARSHAL, "demarshal thread started: id %d", thr_id);

	int id_cntr = 0;

	// Demarshal transactions from the socket.
	for ( ; ; ) {
		cf_poll_event events[POLL_SZ];

		cf_detail(AS_DEMARSHAL, "calling epoll");

		nevents = cf_poll_wait(poll, events, POLL_SZ, -1);

		if (0 > nevents) {
			cf_debug(AS_DEMARSHAL, "epoll_wait() returned %d ; errno = %d (%s)", nevents, errno, cf_strerror(errno));
		}

		cf_detail(AS_DEMARSHAL, "epoll event received: nevents %d", nevents);

		uint64_t now_ns = cf_getns();
		uint64_t now_ms = now_ns / 1000000;

		// Iterate over all events.
		for (i = 0; i < nevents; i++) {
			cf_socket **ssock = events[i].data;

			if (ssock == &s->sock || ssock == &ls->sock || ssock == &xs->sock) {
				// Accept new connections on the service socket.
				cf_socket *csock;
				cf_sock_addr sa;

				if (cf_socket_accept(*ssock, &csock, &sa) < 0) {
					// This means we're out of file descriptors - could be a SYN
					// flood attack or misbehaving client. Eventually we'd like
					// to make the reaper fairer, but for now we'll just have to
					// ignore the accept error and move on.
					if ((errno == EMFILE) || (errno == ENFILE)) {
						if (last_fd_print != (cf_getms() / 1000L)) {
							cf_warning(AS_DEMARSHAL, "Hit OS file descriptor limit (EMFILE on accept). Consider raising limit for uid %d", g_config.uid);
							last_fd_print = cf_getms() / 1000L;
						}
						continue;
					}
					cf_crash(AS_DEMARSHAL, "accept: %s (errno %d)", cf_strerror(errno), errno);
				}

				char sa_str[sizeof(((as_file_handle *)NULL)->client)];
				cf_sock_addr_to_string_safe(&sa, sa_str, sizeof(sa_str));
				cf_detail(AS_DEMARSHAL, "new connection: %s (fd %d)", sa_str, CSFD(csock));

				// Validate the limit of protocol connections we allow.
				uint32_t conns_open = g_stats.proto_connections_opened - g_stats.proto_connections_closed;
				if (ssock != &xs->sock && conns_open > g_config.n_proto_fd_max) {
					if ((last_fd_print + 5000L) < cf_getms()) { // no more than 5 secs
						cf_warning(AS_DEMARSHAL, "dropping incoming client connection: hit limit %d connections", conns_open);
						last_fd_print = cf_getms();
					}
					cf_socket_shutdown(csock);
					cf_socket_close(csock);
					continue;
				}

				// Set the socket to nonblocking.
				cf_socket_disable_blocking(csock);

				// Create as_file_handle and queue it up in epoll_fd for further
				// communication on one of the demarshal threads.
				as_file_handle *fd_h = cf_rc_alloc(sizeof(as_file_handle));
				if (!fd_h) {
					cf_crash(AS_DEMARSHAL, "malloc");
				}

				strcpy(fd_h->client, sa_str);
				fd_h->sock = csock;

				fd_h->last_used = cf_getms();
				fd_h->reap_me = false;
				fd_h->trans_active = false;
				fd_h->proto = 0;
				fd_h->proto_unread = 0;
				fd_h->fh_info = 0;
				fd_h->security_filter = as_security_filter_create();

				// Insert into the global table so the reaper can manage it. Do
				// this before queueing it up for demarshal threads - once
				// EPOLL_CTL_ADD is done it's difficult to back out (if insert
				// into global table fails) because fd state could be anything.
				cf_rc_reserve(fd_h);

				pthread_mutex_lock(&g_file_handle_a_LOCK);

				int j;
				bool inserted = true;

				if (0 != cf_queue_pop(g_freeslot, &j, CF_QUEUE_NOWAIT)) {
					inserted = false;
				}
				else {
					g_file_handle_a[j] = fd_h;
				}

				pthread_mutex_unlock(&g_file_handle_a_LOCK);

				if (!inserted) {
					cf_info(AS_DEMARSHAL, "unable to add socket to file handle table");
					cf_socket_shutdown(csock);
					cf_socket_close(csock);
					cf_rc_free(fd_h); // will free even with ref-count of 2
				}
				else {
					// Round-robin pick up demarshal thread epoll_fd and add
					// this new connection to epoll.
					int id = (id_cntr++) % g_demarshal_args->num_threads;
					fd_h->poll = g_demarshal_args->polls[id];

					// Place the client socket in the event queue.
					cf_poll_add_socket(fd_h->poll, csock, EPOLLIN | EPOLLET | EPOLLRDHUP, fd_h);
					cf_atomic64_incr(&g_stats.proto_connections_opened);
				}
			}
			else {
				bool has_extra_ref   = false;
				as_file_handle *fd_h = events[i].data;
				if (fd_h == 0) {
					cf_info(AS_DEMARSHAL, "event with null handle, continuing");
					goto NextEvent;
				}

				cf_detail(AS_DEMARSHAL, "epoll connection event: fd %d, events 0x%x", CSFD(fd_h->sock), events[i].events);

				// Process data on an existing connection: this might be more
				// activity on an already existing transaction, so we have some
				// state to manage.
				as_proto *proto_p = 0;
				cf_socket *sock = fd_h->sock;

				if (events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
					cf_detail(AS_DEMARSHAL, "proto socket: remote close: fd %d event %x", CSFD(sock), events[i].events);
					// no longer in use: out of epoll etc
					goto NextEvent_FD_Cleanup;
				}

				if (fd_h->trans_active) {
					goto NextEvent;
				}

				// If pointer is NULL, then we need to create a transaction and
				// store it in the buffer.
				if (fd_h->proto == NULL) {
					as_proto proto;
					int sz = cf_socket_available(sock);

					// If we don't have enough data to fill the message buffer,
					// just wait and we'll come back to this one. However, we'll
					// let messages with zero size through, since they are
					// likely errors. We don't cleanup the FD in this case since
					// we'll get more data on it.
					if (sz < sizeof(as_proto) && sz != 0) {
						goto NextEvent;
					}

					// Do a preliminary read of the header into a stack-
					// allocated structure, so that later on we can allocate the
					// entire message buffer.
					if (0 >= (n = cf_socket_recv(sock, &proto, sizeof(as_proto), MSG_WAITALL))) {
						cf_detail(AS_DEMARSHAL, "proto socket: read header fail: error: rv %d sz was %d errno %d", n, sz, errno);
						goto NextEvent_FD_Cleanup;
					}

					if (proto.version != PROTO_VERSION &&
							// For backward compatibility, allow version 0 with
							// security messages.
							! (proto.version == 0 && proto.type == PROTO_TYPE_SECURITY)) {
						cf_warning(AS_DEMARSHAL, "proto input from %s: unsupported proto version %u",
								fd_h->client, proto.version);
						goto NextEvent_FD_Cleanup;
					}

					// Swap the necessary elements of the as_proto.
					as_proto_swap(&proto);

					if (proto.sz > PROTO_SIZE_MAX) {
						cf_warning(AS_DEMARSHAL, "proto input from %s: msg greater than %d, likely request from non-Aerospike client, rejecting: sz %"PRIu64,
								fd_h->client, PROTO_SIZE_MAX, (uint64_t)proto.sz);
						goto NextEvent_FD_Cleanup;
					}

#ifdef USE_JEM
					// Attempt to peek the namespace and set the JEMalloc arena accordingly.
					size_t peeked_data_sz = 0;
					size_t min_field_sz = sizeof(uint32_t) + sizeof(char);
					size_t min_as_msg_sz = sizeof(as_msg) + min_field_sz;
					size_t peekbuf_sz = 2048; // (Arbitrary "large enough" size for peeking the fields of "most" AS_MSGs.)
					uint8_t peekbuf[peekbuf_sz];
					if (PROTO_TYPE_AS_MSG == proto.type) {
						size_t offset = sizeof(as_msg);
						// Number of bytes to peek from the socket.
//						size_t peek_sz = peekbuf_sz;                 // Peak up to the size of the peek buffer.
						size_t peek_sz = MIN(proto.sz, peekbuf_sz);  // Peek only up to the minimum necessary number of bytes.
						int32_t tmp = cf_socket_recv(sock, peekbuf, peek_sz, 0);
						peeked_data_sz = tmp < 0 ? 0 : tmp;
						if (!peeked_data_sz) {
							// That's actually legitimate. The as_proto may have gone into one
							// packet, the as_msg into the next one, which we haven't yet received.
							// This just "never happened" without async.
							cf_detail(AS_DEMARSHAL, "could not peek the as_msg header, expected %zu byte(s)", peek_sz);
						}
						if (peeked_data_sz > min_as_msg_sz) {
//							cf_debug(AS_DEMARSHAL, "(Peeked %zu bytes.)", peeked_data_sz);
							if (peeked_data_sz > proto.sz) {
								cf_warning(AS_DEMARSHAL, "Received unexpected extra data from client %s socket %d when peeking as_proto!", fd_h->client, CSFD(sock));
								log_as_proto_and_peeked_data(&proto, peekbuf, peeked_data_sz);
								goto NextEvent_FD_Cleanup;
							}

							if (((as_msg*)peekbuf)->info1 & AS_MSG_INFO1_BATCH) {
								jem_set_arena(orig_arena);
							} else {
								uint16_t n_fields = ntohs(((as_msg *) peekbuf)->n_fields), field_num = 0;
								bool found = false;
	//							cf_debug(AS_DEMARSHAL, "Found %d AS_MSG fields", n_fields);
								while (!found && (field_num < n_fields)) {
									as_msg_field *field = (as_msg_field *) (&peekbuf[offset]);
									uint32_t value_sz = ntohl(field->field_sz) - 1;
	//								cf_debug(AS_DEMARSHAL, "Field #%d offset: %lu", field_num, offset);
	//								cf_debug(AS_DEMARSHAL, "\tvalue_sz %u", value_sz);
	//								cf_debug(AS_DEMARSHAL, "\ttype %d", field->type);
									if (AS_MSG_FIELD_TYPE_NAMESPACE == field->type) {
										if (value_sz >= AS_ID_NAMESPACE_SZ) {
											cf_warning(AS_DEMARSHAL, "namespace too long (%u) in as_msg", value_sz);
											goto NextEvent_FD_Cleanup;
										}
										char ns[AS_ID_NAMESPACE_SZ];
										found = true;
										memcpy(ns, field->data, value_sz);
										ns[value_sz] = '\0';
	//									cf_debug(AS_DEMARSHAL, "Found ns \"%s\" in field #%d.", ns, field_num);
										jem_set_arena(as_namespace_get_jem_arena(ns));
									} else {
	//									cf_debug(AS_DEMARSHAL, "Message field %d is not namespace (type %d) ~~ Reading next field", field_num, field->type);
										field_num++;
										offset += sizeof(as_msg_field) + value_sz;
										if (offset >= peeked_data_sz) {
											break;
										}
									}
								}
								if (!found) {
									cf_warning(AS_DEMARSHAL, "Can't get namespace from AS_MSG (peeked %zu bytes) ~~ Using default thr_demarshal arena.", peeked_data_sz);
									jem_set_arena(orig_arena);
								}
							}
						} else {
							jem_set_arena(orig_arena);
						}
					} else {
						jem_set_arena(orig_arena);
					}
#endif

					// Allocate the complete message buffer.
					proto_p = cf_malloc(sizeof(as_proto) + proto.sz);

					cf_assert(proto_p, AS_DEMARSHAL, CF_CRITICAL, "allocation: %zu %s", (sizeof(as_proto) + proto.sz), cf_strerror(errno));
					memcpy(proto_p, &proto, sizeof(as_proto));

#ifdef USE_JEM
					// Jam in the peeked data.
					if (peeked_data_sz) {
						memcpy(proto_p->data, &peekbuf, peeked_data_sz);
					}
					fd_h->proto_unread = proto_p->sz - peeked_data_sz;
#else
					fd_h->proto_unread = proto_p->sz;
#endif
					fd_h->proto = (void *) proto_p;
				}
				else {
					proto_p = fd_h->proto;
				}

				if (fd_h->proto_unread > 0) {

					// Read the data.
					n = cf_socket_recv(sock, proto_p->data + (proto_p->sz - fd_h->proto_unread), fd_h->proto_unread, 0);
					if (0 >= n) {
						if (n < 0 && errno == EAGAIN) {
							continue;
						}
						cf_info(AS_DEMARSHAL, "receive socket: fail? n %d errno %d %s closing connection.", n, errno, cf_strerror(errno));
						goto NextEvent_FD_Cleanup;
					}

					// Decrement bytes-unread counter.
					cf_detail(AS_DEMARSHAL, "read fd %d (%d %"PRIu64")", CSFD(sock), n, fd_h->proto_unread);
					fd_h->proto_unread -= n;
				}

				// Check for a finished read.
				if (0 == fd_h->proto_unread) {

					// It's only really live if it's injecting a transaction.
					fd_h->last_used = now_ms;

					thr_demarshal_pause(fd_h); // pause reading while the transaction is in progress
					fd_h->proto = 0;
					fd_h->proto_unread = 0;

					cf_rc_reserve(fd_h);
					has_extra_ref = true;

					// Info protocol requests.
					if (proto_p->type == PROTO_TYPE_INFO) {
						as_info_transaction it = { fd_h, proto_p, now_ns };

						as_info(&it);
						goto NextEvent;
					}

					// INIT_TR
					as_transaction tr;
					as_transaction_init_head(&tr, NULL, (cl_msg *)proto_p);

					tr.origin = FROM_CLIENT;
					tr.from.proto_fd_h = fd_h;
					tr.start_time = now_ns;

					if (! as_proto_is_valid_type(proto_p)) {
						cf_warning(AS_DEMARSHAL, "unsupported proto message type %u", proto_p->type);
						// We got a proto message type we don't recognize, so it
						// may not do any good to send back an as_msg error, but
						// it's the best we can do. At least we can keep the fd.
						as_transaction_demarshal_error(&tr, AS_PROTO_RESULT_FAIL_UNKNOWN);
						goto NextEvent;
					}

					// Check if it's compressed.
					if (tr.msgp->proto.type == PROTO_TYPE_AS_MSG_COMPRESSED) {
						// Decompress it - allocate buffer to hold decompressed
						// packet.
						uint8_t *decompressed_buf = NULL;
						size_t decompressed_buf_size = 0;
						int rv = 0;
						if ((rv = as_packet_decompression((uint8_t *)proto_p, &decompressed_buf, &decompressed_buf_size))) {
							cf_warning(AS_DEMARSHAL, "as_proto decompression failed! (rv %d)", rv);
							cf_warning_binary(AS_DEMARSHAL, proto_p, sizeof(as_proto) + proto_p->sz, CF_DISPLAY_HEX_SPACED, "compressed proto_p");
							as_transaction_demarshal_error(&tr, AS_PROTO_RESULT_FAIL_UNKNOWN);
							goto NextEvent;
						}

						// Free the compressed packet since we'll be using the
						// decompressed packet from now on.
						cf_free(proto_p);
						proto_p = NULL;
						// Get original packet.
						tr.msgp = (cl_msg *)decompressed_buf;
						as_proto_swap(&(tr.msgp->proto));

						if (! as_proto_wrapped_is_valid(&tr.msgp->proto, decompressed_buf_size)) {
							cf_warning(AS_DEMARSHAL, "decompressed unusable proto: version %u, type %u, sz %lu [%lu]",
									tr.msgp->proto.version, tr.msgp->proto.type, (uint64_t)tr.msgp->proto.sz, decompressed_buf_size);
							as_transaction_demarshal_error(&tr, AS_PROTO_RESULT_FAIL_UNKNOWN);
							goto NextEvent;
						}
					}

					// If it's an XDR connection and we haven't yet modified the connection settings, ...
					if (tr.msgp->proto.type == PROTO_TYPE_AS_MSG &&
							as_transaction_is_xdr(&tr) &&
							(fd_h->fh_info & FH_INFO_XDR) == 0) {
						// ... modify them.
						if (thr_demarshal_config_xdr(fd_h->sock) != 0) {
							cf_warning(AS_DEMARSHAL, "Failed to configure XDR connection");
							goto NextEvent_FD_Cleanup;
						}

						fd_h->fh_info |= FH_INFO_XDR;
					}

					// Security protocol transactions.
					if (tr.msgp->proto.type == PROTO_TYPE_SECURITY) {
						as_security_transact(&tr);
						goto NextEvent;
					}

					// For now only AS_MSG's contribute to this benchmark.
					if (g_config.svc_benchmarks_enabled) {
						tr.benchmark_time = histogram_insert_data_point(g_stats.svc_demarshal_hist, now_ns);
					}

					// Fast path for batch requests.
					if (tr.msgp->msg.info1 & AS_MSG_INFO1_BATCH) {
						as_batch_queue_task(&tr);
						goto NextEvent;
					}

					// Swap as_msg fields and bin-ops to host order, and flag
					// which fields are present, to reduce re-parsing.
					if (! as_transaction_demarshal_prepare(&tr)) {
						as_transaction_demarshal_error(&tr, AS_PROTO_RESULT_FAIL_PARAMETER);
						goto NextEvent;
					}

					ASD_TRANS_DEMARSHAL(nodeid, (uint64_t) tr.msgp, as_transaction_trid(&tr));

					// Either process the transaction directly in this thread,
					// or queue it for processing by another thread (tsvc/info).
					if (0 != thr_tsvc_process_or_enqueue(&tr)) {
						cf_warning(AS_DEMARSHAL, "Failed to queue transaction to the service thread");
						goto NextEvent_FD_Cleanup;
					}
				}

				// Jump the proto message free & FD cleanup. If we get here, the
				// above operations went smoothly. The message free & FD cleanup
				// job is handled elsewhere as directed by
				// thr_tsvc_process_or_enqueue().
				goto NextEvent;

NextEvent_FD_Cleanup:
				// If we allocated memory for the incoming message, free it.
				if (proto_p) {
					cf_free(proto_p);
					fd_h->proto = 0;
				}
				// If fd has extra reference for transaction, release it.
				if (has_extra_ref) {
					cf_rc_release(fd_h);
				}
				// Remove the fd from the events list.
				cf_poll_delete_socket(poll, sock);
				pthread_mutex_lock(&g_file_handle_a_LOCK);
				fd_h->reap_me = true;
				as_release_file_handle(fd_h);
				fd_h = 0;
				pthread_mutex_unlock(&g_file_handle_a_LOCK);
NextEvent:
				;
			}

			// We should never be canceled externally, but just in case...
			pthread_testcancel();
		}
	}

	return NULL;
}

// Initialize the demarshal service, start demarshal threads.
int
as_demarshal_start()
{
	demarshal_args *dm = cf_malloc(sizeof(demarshal_args));
	memset(dm, 0, sizeof(demarshal_args));
	g_demarshal_args = dm;

	dm->num_threads = g_config.n_service_threads;

	g_freeslot = cf_queue_create(sizeof(int), true);
	if (!g_freeslot) {
		cf_crash(AS_DEMARSHAL, " Couldn't create reaper free list ");
	}

	// Start the listener socket: note that because this is done after privilege
	// de-escalation, we can't use privileged ports.
	g_config.socket.reuse_addr = g_config.socket_reuse_addr;
	if (0 != cf_socket_init_server(&g_config.socket)) {
		cf_crash(AS_DEMARSHAL, "couldn't initialize service socket");
	}
	cf_socket_disable_blocking(g_config.socket.sock);

	// Note:  The localhost socket address will only be set if the main service socket
	//        is not already (effectively) listening on the localhost address.
	if (g_config.localhost_socket.addr) {
		cf_debug(AS_DEMARSHAL, "Opening a localhost service socket");
		g_config.localhost_socket.reuse_addr = g_config.socket_reuse_addr;
		if (0 != cf_socket_init_server(&g_config.localhost_socket)) {
			cf_crash(AS_DEMARSHAL, "couldn't initialize localhost service socket");
		}
		cf_socket_disable_blocking(g_config.localhost_socket.sock);
	}

	g_config.xdr_socket.port = as_xdr_info_port();

	if (g_config.xdr_socket.port != 0) {
		cf_debug(AS_DEMARSHAL, "Opening XDR service socket");
		g_config.xdr_socket.reuse_addr = g_config.socket_reuse_addr;

		if (0 != cf_socket_init_server(&g_config.xdr_socket)) {
			cf_crash(AS_DEMARSHAL, "Couldn't initialize XDR service socket");
		}

		cf_socket_disable_blocking(g_config.xdr_socket.sock);
	}

	// Create all the epoll_fds and wait for all the threads to come up.
	int i;
	for (i = 1; i < dm->num_threads; i++) {
		if (0 != pthread_create(&(dm->dm_th[i]), 0, thr_demarshal, &g_config.socket)) {
			cf_crash(AS_DEMARSHAL, "Can't create demarshal threads");
		}
	}

	for (i = 1; i < dm->num_threads; i++) {
		while (CEFD(dm->polls[i]) == 0) {
			sleep(1);
			cf_info(AS_DEMARSHAL, "Waiting to spawn demarshal threads ...");
		}
	}

	// Create first thread which is the listener. We do this one last, as it
	// requires the other threads' epoll instances.
	if (0 != pthread_create(&(dm->dm_th[0]), 0, thr_demarshal, &g_config.socket)) {
		cf_crash(AS_DEMARSHAL, "Can't create demarshal threads");
	}
	while (CEFD(dm->polls[0]) == 0) {
		sleep(1);
	}

	cf_info(AS_DEMARSHAL, "Started %d Demarshal Threads", dm->num_threads);

	return 0;
}
