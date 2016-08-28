/*
 * hb.c
 *
 * Copyright (C) 2012-2016 Aerospike, Inc.
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

#include "fabric/hb.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/param.h> // For MAX() and MIN().
#include <sys/socket.h>
#include <sys/types.h>
#include <zlib.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_queue.h"
#include "citrusleaf/cf_shash.h"

#include "fault.h"
#include "socket.h"

#include "base/cfg.h"
#include "base/stats.h"
#include "fabric/fabric.h"

/*
 * Overview
 * ========
 *debug
 * The heartbeat subsystem is a core clustering module that discovers nodes in
 * the cluster and monitors connectivity to them. This subsystem maintains an
 * "adjacency list", which is the list of nodes deemed to be alive and connected
 * at any instance in time.
 *
 * The heartbeat subsystem is divided into three submodules
 *  1. Config
 *  2. Channel
 *  3. Mesh
 *  4. Main
 *
 * Config
 * ------
 * This submodule deals with overall heartbeat subsystem configuration and
 dynamic updates to configuration.
 *
 * Channel
 * -------
 * This submodule is responsible for maintaining a channel between this node and
 * all known nodes. The channel submodule provides the ability to broadcast /
 * unicast messages to known nodes.
 *
 * Other modules interact with the channel submodule primarily through events
 * raised by the channel submodule. The events help other submodules infer
 * connectivity status to known nodes and react to incoming heartbeat message
 * from other nodes.
 *
 * Depending on the configured mode (mesh. multicast) the channels between this
 * node and other nodes could be
 * 1. TCP and hence unicast. One per pair of nodes.
 * 2. Multicast with UDP. One per cluster.
 *
 * Mesh
 * ----
 * This submodule is responsible for discovering cluster members. New nodes are
 * discovered via adjacency lists published in their heartbeats of know nodes.
 * The mesh module boots up using configured seed nodes.
 *
 * Main
 * ----
 * This submodule orchestrates other modules and hence main. Its primary
 * responsibility is to maintain the adjacency list.
 *
 * Heartbeat messages
 * ==================
 *
 * Every heartbeat message contains
 *  1. the source node's nodeid
 *  2. the source node's published ip address
 *  3. the source node's published port.

 * There are the following types of heartbeat messages
 *  1. Pulse - messages sent at periodic intervals. Will contain current
 *  adjacency lists
 *  2. Info request - message sent in the mesh mode, to a known mesh node,
 *  in order to get ip address and port of a newly discovered node.
 *  3. Info reply - message sent in response to an info request. Returns
 *  the node's ip address and port.
 *
 * Message conventions
 * -------------------
 * 1. Published adjacency will always contain the source node.
 *
 * Design philosophy
 * =================
 *
 * Locking vs single threaded event loop.
 * --------------------------------------
 * This first cut leans toward using locks instead of single threaded event
 * loops to protect critical data. The choice is driven by the fact that
 * synchronous external and inter-submodule interaction looked like more work
 * with single threaded event loops. The design chooses simplicity over
 * performance given the lower volumes of events that need to be processed here
 * as compared to the transaction processing code. The locks are coarse, one per
 * submodule and reentrant. They are used generously and no function makes an
 * assumption of locks prior locks being held.
 *
 * Inter-module interactions in some cases are via synchronous function calls,
 * which run the risk of deadlocks. For now, deadlocks should not happen.
 * However, if this idealogy complicates code, inter-module interaction will be
 * rewritten to use asynchronous event queues.
 *
 * Locking policy
 * ==============
 *
 * 1. Lock as much as you can. The locks are re-entrant. This is not a critical
 *    high volume code path, and hence correctness with simplicity is preferred.
 *    Any read / write access to module state should be under a lock.
 * 2. Preventing deadlocks
 *    a. The enforced lock order is
 *       1. Protocol lock (SET_PROTOCOL_LOCK) Uses to ensure protocol set is
 atomic.
 *       2. Main module (HB_LOCK)
 *       3. Mesh and multicast modules (MESH_LOCK)
 *       4. Channel (CHANNEL_LOCK)
 *       5. Config (CONFIG_LOCK)
 *     Always make sure every thread acquires locks in this order ONLY.
 * 3. Events raised / messages passed to listeners should be outside the
 *    module's lock.
 *
 * Guidelines for message plugins
 * ==============================
 * The parse data functions should NOT hold any locks and thus avert deadlocks.
 *
 * Notable changes vis-a-vis v3/4
 * ==============================
 *
 * 1. Mesh discovery now based on exchanged adjacency list instead of succession
 * lists.
 *
 * 2. In mesh mode only one TCP connection maintained per external node. (There
 * is a small window when there can be two connections but one would be closed
 * down.) This also means lesser bandwidth utilized by the heartbeat subsystem.
 *
 * 3. The maximum cluster size is practically unlimited in the mesh mode and
 * limited by how many nodes can be shipped with succession and adjacency lists
 * in the underlying multicast channel MTU. This parameter will be deprecated.
 *
 * 4. Network packets now consume space proportional to the number of elements
 * in the adjacency list and the succession list rather than a configured max
 * cluster size.
 *
 * 5. In mesh node, due to the fact that tcp messages can be variable sized now,
 * the info request and reply can query and reply for a batch of new nodes
 instead
 * of just one.
 *
 * 6. Mesh seed node allows hostnames in the config file.
 *
 * 7. External modules can register as a plugin and send and receive module
 * specific data via heartbeat messages. Paxos uses this mechanism instead, to
 * publish succession lists.
 *
 * TODO
 * ====
 * 1. Extend to allow hostnames in mesh mode across the board.
 */

/*----------------------------------------------------------------------------
 * Private internal data structures.
 *----------------------------------------------------------------------------*/

/* ---- Common ---- */

/**
 * An immutable heartbeat subsystem end point. Not meant to be updated once
 * created.
 */
typedef struct as_hb_endpoint_s
{
	/**
	 * The ip address for the endpoint. Can be ipv4 / ipv6. cf_sockaddr
	 * contains the port as well.
	 */
	as_hb_ipaddr addr;

	/**
	 * The hb port for this endpoint.
	 */
	uint32_t port;

} __attribute__((__packed__)) as_hb_endpoint;

/**
 * Message formats for logging heartbeat error event.
 */
typedef enum as_hb_err_msg_format_e {
	LONG_FORMAT = 0,
	SHORT_FORMAT
} as_hb_err_msg_format;

/**
 * Names of the types of heartbeat errors.
 * NOTE:  Must match the number and order of "as_hb_err_type".
 */
char* as_hb_error_msg[][2] = {
	// clang-format off
	{ "no source node", "ns"},
	{ "no type", "nt", },
	{ "no id", "ni", },
	{ "hb mismatch", "hbm"},
	{ "no endpoint", "ne", },
	{ "no send timestamp", "nst", },
	{ "no node in info request", "nnir", },
	{ "no node in info reply", "nnirp", },
	{ "no anv length", "nal", },
	{ "max cluster size mismatch", "mcsm", },
	{ "send info request fail", "sirf", },
	{ "send info reply fail", "sirpf", },
	{ "send broadcast fail", "sbf", },
	{ "expire hb", "eh", },
	{ "expire fab dead", "efd", },
	{ "expire fab alive", "efa", },
	{ "unparsable msg", "um" },
	{ "mesh connect fail", "mcf" },
	{ "remote close", "rc" },
	{ "mtu breach", "mtub" }
	// clang-format on
};

// Occurrence counts for each type of heartbeat error detected.
static uint64_t as_hb_error_count[AS_HB_ERR_MAX_TYPE] = { 0 };

// Verify that the enum and the string arrays have the same length.
COMPILER_ASSERT(sizeof(as_hb_error_msg) / (sizeof(char * [2])) ==
		AS_HB_ERR_MAX_TYPE);

/**
 * Heartbeat subsystem state.
 */
typedef enum {
	AS_HB_STATUS_UNINITIALIZED,
	AS_HB_STATUS_RUNNING,
	AS_HB_STATUS_SHUTTING_DOWN,
	AS_HB_STATUS_STOPPED
} as_hb_status;

/* ---- Mesh related ---- */

/**
 * The info payload for a single node.
 */
typedef struct as_hb_mesh_info_reply_s
{
	/**
	 * The nodeid of the node for which info reply is sent.
	 */
	cf_node nodeid;

	/**
	 * The endpoint for this node.
	 */
	as_hb_endpoint endpoint;
} __attribute__((__packed__)) as_hb_mesh_info_reply;

/**
 * Mesh tend reduce function udata.
 */
typedef struct
{
	/**
	 * The new endpoints to connect to.
	 */
	as_hb_endpoint* to_connect;

	/**
	 * The capacity of the to connect array.
	 */
	size_t to_connect_capacity;

	/**
	 * The count of endpoints to connect.
	 */
	size_t to_connect_count;

} as_hb_mesh_tend_reduce_udata;

/**
 * A composite key created from the mesh nodeid and a flag indicating if its
 * fake or real.
 */
typedef struct
{
	/**
	 * Indicates if the contained nodeid is real.
	 */
	bool is_real_nodeid;

	/**
	 * The nodeid real or fake.
	 */
	cf_node nodeid;
} __attribute__((__packed__)) as_hb_mesh_node_key;

/**
 * Mesh endpoint search udata.
 */
typedef struct
{
	/**
	 * The endpoint to search.
	 */
	as_hb_endpoint* to_search;

	/**
	 * Indicates is a match is found.
	 */
	bool found;

	/**
	 * The count of endpoints to connect.
	 */
	as_hb_mesh_node_key* matched_key;
} as_hb_mesh_endpoint_reduce_udata;

typedef enum {
	/**
	 * The mesh node has an active channel.
	 */
	AS_HB_MESH_NODE_CHANNEL_ACTIVE,

	/**
	 * The mesh node is waiting for an active channel.
	 */
	AS_HB_MESH_NODE_CHANNEL_PENDING,

	/**
	 * The mesh node does not have an active channel.
	 */
	AS_HB_MESH_NODE_CHANNEL_INACTIVE,

	/**
	 * The ip address and port for this node are not yet known. This is also
	 * the
	 * sentinel value for this enum and MUST be the last value here.
	 */
	AS_HB_MESH_NODE_ENDPOINT_UNKNOWN

} as_hb_mesh_node_status;

/**
 * Information maintained for discovered mesh end points.
 */
typedef struct as_hb_mesh_node_s
{
	/**
	 * The node id. A zero will indicate that the nodeid is not yet known.
	 */
	cf_node nodeid;

	/**
	 * Indicates if this node is a seed node.
	 */
	bool is_seed;

	/**
	 * The name / ip address of this mesh host.
	 */
	char mesh_host_name[HOST_NAME_MAX];

	/**
	 * The end point for this mesh host.
	 */
	as_hb_endpoint endpoint;

	/**
	 * The state of this node in terms of established channel.
	 */
	as_hb_mesh_node_status status;

	/**
	 * The last time the state of this node was updated.
	 */
	cf_clock last_status_updated;

	/**
	 * The time this's node channel become inactive.
	 */
	cf_clock inactive_since;

} as_hb_mesh_node;

/**
 * State maintained for the mesh mode.
 */
typedef struct as_hb_mesh_state_s
{
	/**
	 * The socket on which this instance received heartbeat tcp connections.
	 */
	cf_socket_cfg socket;

	/**
	 * A map from an as_hb_mesh_node_key to a mesh node. A random nodeid
	 * will be used as a key if the nodeid is unknown. Once the nodeid is
	 * known the value will be moved to a new key.
	 */
	shash* nodeid_to_mesh_node;

	/**
	 * Thread id for the mesh tender thread.
	 */
	pthread_t mesh_tender_tid;

	/**
	 * The status of the mesh module.
	 */
	as_hb_status status;

	/**
	 * The mtu on the listening device. This is extrapolated to all nodes
	 * and paths in the cluster. This limits the cluster size possible.
	 */
	int min_mtu;

} as_hb_mesh_state;

/* ---- Multicast data structures ---- */

/**
 * State maintained for the multicast mode.
 */
typedef struct as_hb_multicast_state_s
{
	/**
	 * The socket associated with multicast mode.
	 */
	cf_socket_mcast_cfg socket;

	/**
	 * The mtu on the listening device. This is extrapolated to all nodes
	 * and paths in the cluster. This limits the cluster size possible.
	 */
	int min_mtu;

} as_hb_multicast_state;

/* ---- Channel state ---- */

typedef struct
{

	/**
	 * The endpoint to search.
	 */
	as_hb_endpoint* endpoint;

	/**
	 * Indicates if the endpoint was found.
	 */
	bool found;

	/**
	 * The matching socket, if found.
	 */
	cf_socket* socket;

} as_hb_channel_endpoint_reduce_udata;

typedef struct
{

	/**
	 * The new endpoints to connect to. Input field.
	 */
	uint8_t* buffer;

	/**
	 * Indicates if the endpoint was found.
	 */
	size_t buffer_len;

} as_hb_channel_buffer_udata;

/**
 * A channel represents a medium to send and receive messages.
 */
typedef struct as_hb_channel_s
{
	/**
	 * Inidicates if this channel is a multicast channel.
	 */
	bool is_multicast;

	/**
	 * Indicates if this channel is inbound. Not relevant for multicast
	 * channels.
	 */
	bool is_inbound;

	/**
	 * The id of the associated node. In mesh / unicast case this will
	 * initially be zeor and filled in when the nodeid for the node at the
	 * other end is learnt. In multicast case this will be zero.
	 */
	cf_node nodeid;

	/**
	 * The address of the peer. For now only valid for outbound channels.
	 */
	as_hb_endpoint endpoint;

	/**
	 * The last time a message was received from this node.
	 */
	cf_clock last_received;

	/**
	 * Time when this channel won a socket resolution. Zero if this channel
	 * never won resolution. In compatibility mode with older code its
	 * possible we will keep allowing the same socket to win and enter an
	 * infinite loop of closing the sockets.
	 */
	cf_clock resolution_win_ts;

} as_hb_channel;

/**
 * State maintained per heartbeat channel.
 */
typedef struct as_hb_channel_state_s
{
	/**
	 * The poll handle. All IO wait across all heartbeat connections happens
	 * on
	 * this handle.
	 */
	cf_poll poll;

	/**
	 * Channel status.
	 */
	as_hb_status status;

	/**
	 * Maps a socket to an as_hb_channel.
	 */
	shash* socket_to_channel;

	/**
	 * Maps a nodeid to a channel specific node data structure. This
	 * association will be made
	 * only on receiving the first heartbeat message from the node on a
	 * channel.
	 */
	shash* nodeid_to_socket;

	/**
	 * Sockets accumulated by the channel tender to close at the end of every
	 * epoll loop.
	 */
	cf_queue socket_close_queue;

	/**
	 * The socket on which heartbeart subsystem listens to.
	 */
	cf_socket* listening_socket;

	/**
	 * Enables / disables publishing channel events. Events should be
	 * disabled only when the state changes are temporary / transient and
	 * hence would not change the overall channel state from an external
	 * perspective.
	 */
	bool events_enabled;

	/**
	 * Events are batched and published to reduce cluster transitions. Queue
	 * of unpublished heartbeat
	 * events.
	 */
	cf_queue events_queue;

	/**
	 * Thread id for the socket tender thread.
	 */
	pthread_t channel_tender_tid;

} as_hb_channel_state;

/**
 * Entry queued up for socket close.
 */
typedef struct as_hb_channel_socket_close_entry_s
{
	/**
	 * The node for which this event was generated.
	 */
	cf_socket* socket;
	/**
	 * Inidicates if this close is a remote close.
	 */
	bool is_remote;
	/**
	 * True if close of this entry should generate a disconnect event.
	 */
	bool raise_close_event;
} as_hb_channel_socket_close_entry;

/**
 * The type of a channel event.
 */
typedef enum {
	/**
	 * The endpoint has a channel tx/rx channel associated with it.
	 */
	AS_HB_CHANNEL_NODE_CONNECTED,

	/**
	 * The endpoint had a tx/rx channel that went down.
	 */
	AS_HB_CHANNEL_NODE_DISCONNECTED,

	/**
	 * A message was received on a connected channel. The message
	 * in the event, is guaranteed to have passed basic sanity check like
	 * have protocol id, type and source nodeid.
	 */
	AS_HB_CHANNEL_MSG_RECEIVED

} as_hb_channel_event_type;

/**
 * An event generated by the channel submodule.
 */
typedef struct as_hb_channel_event_s
{
	/**
	 * The channel event type.
	 */
	as_hb_channel_event_type type;

	/**
	 * The node for which this event was generated.
	 */
	cf_node nodeid;

	/**
	 * The received message if any over this endpoint. Valid for incoming
	 * message type event. The message if not NULL never be edited or copied
	 * over.
	 */
	msg* msg;

	/**
	 * The peer endpoint on which this message was received. Valid only for
	 * incoming message type event.
	 */
	as_hb_endpoint peer_endpoint;

	/**
	 * The hlc timestamp for message receipt.
	 */
	as_hlc_msg_timestamp msg_hlc_ts;

} as_hb_channel_event;

/**
 * Status for reads from a channel.
 */
typedef enum {
	/**
	 * The message was read successfully and parser.
	 */
	AS_HB_CHANNEL_MSG_READ_SUCCESS,

	/**
	 * The message read successfully but parsing failed.
	 */
	AS_HB_CHANNEL_MSG_PARSE_FAIL,

	/**
	 * The message type does not match the expected message type.
	 */
	AS_HB_CHANNEL_MSG_TYPE_FAIL,

	/**
	 * The message read failed network io.
	 */
	AS_HB_CHANNEL_MSG_CHANNEL_FAIL,

	/**
	 * Sentinel default value.
	 */
	AS_HB_CHANNEL_MSG_READ_UNDEF

} as_hb_channel_msg_read_status;

/* ---- Main submodule state ---- */

/**
 * Heartbeat message types.
 */
typedef enum {
	AS_HB_MSG_TYPE_PULSE,
	AS_HB_MSG_TYPE_INFO_REQUEST,
	AS_HB_MSG_TYPE_INFO_REPLY,
	AS_HB_MSG_TYPE_COMPRESSED
} as_hb_msg_type;

/**
 * State maintained by the heartbeat subsystem for the selected mode.
 */
typedef struct as_hb_mode_state_s
{
	/**
	 * The mesh / mcast state.
	 */
	union
	{
		as_hb_mesh_state mesh_state;
		as_hb_multicast_state multicast_state;
	};

} as_hb_mode_state;

/**
 * Plugin data iterate reduce udata.
 */
typedef struct
{
	/**
	 * The plugin id.
	 */
	as_hb_plugin_id pluginid;

	/**
	 * The iterate function.
	 */
	as_hb_plugin_data_iterate_fn iterate_fn;

	/**
	 * The udata for the iterate function.
	 */
	void* udata;

} as_hb_adjacecny_iterate_reduce_udata;

/**
 * Information tracked for an adjacent nodes.
 */
typedef struct as_hb_adjacent_node_s
{

	/**
	 * The heart beat protocol version.
	 */
	uint32_t hb_protocol_version;

	/**
	 * The node's ip address.
	 */
	as_hb_ipaddr addr;

	/**
	 * Used to cycle between the two copies of plugin data.
	 */
	int plugin_data_cycler;

	/**
	 * Plugin specific data accumulated for by the heartbeat subsystem. The
	 * data  is heap allocated and should be destroyed the moment this
	 * element entry is unused. There are two copies of the plugni data, one
	 * the current copy and one the previous copy. Previous copy is used to
	 * generate data change notifications.
	 */
	as_hb_plugin_node_data plugin_data[AS_HB_PLUGIN_SENTINEL][2];

	/**
	 * The monotonic local time time node information was last updated.
	 */
	cf_clock lasted_updated_monotonic_ts;

	/**
	 * Timestamp for the last pulse message.
	 */
	as_hlc_msg_timestamp last_msg_hlc_ts;

} as_hb_adjacent_node;

/**
 * Internal storage for external event listeners.
 */
typedef struct as_hb_event_listener_s
{
	as_hb_event_fn event_callback;
	void* udata;
} as_hb_event_listener;

/**
 * Maximum event listeners.
 */
#define AS_HB_EVENT_LISTENER_MAX (7)

/**
 * Heartbeat subsystem internal state.
 */
typedef struct as_hb_s
{

	/**
	 * The status of the subsystem.
	 */
	as_hb_status status;

	/**
	 * The adjacency dictionary. The key is the nodeid. The value is an
	 * instance of as_hb_adjacent_node.
	 */
	shash* adjacency;

	/**
	 * The mode specific state.
	 */
	as_hb_mode_state mode_state;

	/**
	 * The channel state.
	 */
	as_hb_channel_state channel_state;

	/**
	 * The plugin dictionary. The key is the as_hb_plugin entry and the
	 * value an instance of as_hb_plugin.
	 */
	as_hb_plugin plugins[AS_HB_PLUGIN_SENTINEL];

	/**
	 * Thread id for the transmitter thread.
	 */
	pthread_t transmitter_tid;

	/**
	 * Thread id for the thread expiring nodes from the adjacency list.
	 */
	pthread_t adjacency_tender_tid;

} as_hb;

/**
 * Registered heartbeat listeners.
 */
typedef struct as_hb_external_events_s
{
	/**
	 * Events are batched and published. Queue of unpublished heartbeat
	 * events.
	 */
	cf_queue external_events_queue;

	/**
	 * Time when the last events publish was done.
	 */
	cf_clock external_events_published_last;

	/**
	 * Count of event listeners.
	 */
	int event_listener_count;

	/**
	 * External event listeners.
	 */
	as_hb_event_listener event_listeners[AS_HB_EVENT_LISTENER_MAX];
} as_hb_external_events;

/**
 * Shash reduce function to read current adjacency list.
 */
typedef struct as_hb_adjacency_reduce_udata_s
{
	/**
	 * The adjaceny list.
	 */
	cf_node* adj_list;

	/**
	 * Count of elements in the adjacecny list.
	 */
	int adj_count;
} as_hb_adjacency_reduce_udata;

/**
 *  Udata for finding nodes in the adjaceny list not in the input succession
 * list.
 */
typedef struct
{
	int event_count;
	as_hb_event_node* events;
	int max_events;
	cf_node* succession;
	int succession_size;
} as_hb_find_new_nodes_reduce_udata;

/**
 * Shash reduce function to read current adjacency list.
 */
typedef struct as_hb_adjacency_tender_udata_s
{
	/**
	 * The adjaceny list.
	 */
	cf_node* dead_node_list;

	/**
	 * Count of elements in the adjacecny list.
	 */
	int dead_node_count;
} as_hb_adjacency_tender_udata;

/**
 * Udata for finding sockets open in channel.
 */
typedef struct as_hb_sockets_udata_s
{
	/**
	 * List of sockets.
	 */
	cf_vector socketss;

	/**
	 * count of elements in the socket list.
	 */
	int sockets_count;
} as_hb_sockets_udata;

/**
 * Udata for tip clear.
 **/
typedef struct as_hb_mesh_tip_clear_udata_s
{
	char host[HOST_NAME_MAX];
	int port;
} as_hb_mesh_tip_clear_udata;

/*----------------------------------------------------------------------------
 * Globals.
 *----------------------------------------------------------------------------*/
/**
 * Legacy heartbeat protocol identifiers.
 */
#define AS_HB_PROTOCOL_V1_IDENTIFIER 0x6862
#define AS_HB_PROTOCOL_V2_IDENTIFIER 0x6863

/**
 * The identifier for heartbeat protocol version 3.
 */
#define AS_HB_PROTOCOL_V3_IDENTIFIER 0x6864

/**
 * Get hold of current heartbeat protocol version
 */
#define AS_HB_PROTOCOL_IDENTIFIER()                                            \
	(AS_HB_PROTOCOL_V1 == config_protocol_get()                            \
	   ? AS_HB_PROTOCOL_V1_IDENTIFIER                                      \
	   : (AS_HB_PROTOCOL_V2 == config_protocol_get()                       \
		? AS_HB_PROTOCOL_V2_IDENTIFIER                                 \
		: AS_HB_PROTOCOL_V3_IDENTIFIER))

/**
 * MAximum length of hb protocol string.
 */
#define AS_HB_PROTOCOL_STR_MAX_LEN() (16)

/**
 * Check if heartbeat is running a legacy protocol.
 */
#define HB_IS_PROTOCOL_LEGACY()                                                \
	(AS_HB_PROTOCOL_V1 == config_protocol_get() ||                         \
	 AS_HB_PROTOCOL_V2 == config_protocol_get())

/**
 * Check the message is a legacy protocol message.
 */
#define HB_IS_MSG_LEGACY(msg) (msg->type == M_TYPE_HEARTBEAT_V2 ? true : false)

/**
 * Timeout for deeming a node dead based on received heartbeats.
 */
#define AS_HB_NODE_TIMEOUT()                                                   \
	((config_hb_max_intervals_missed_get() * config_hb_tx_interval_get()))

/**
 * Node depart event time estimate. Assumes node departed timeout milliseconds
 * before the detection.
 */
#define NODE_DEPART_TIME(detect_time) ((detect_time)-AS_HB_NODE_TIMEOUT())

/**
 * Interval at which heartbeat subsystem publishes node events to external
 * listeners.
 */
#define AS_HB_EVENT_PUBLISH_INTERVAL() (10)

/**
 * Grace period granted to a node if fabric messages are going across but
 * heartbeat messages are missing.
 */
#define AS_HB_FABRIC_GRACE_PERIOD()                                            \
	({                                                                     \
		int factor = config_hb_fabric_grace_factor_get();              \
		(uint32_t)(factor >= 0 ? factor * AS_HB_NODE_TIMEOUT()         \
				       : UINT32_MAX);                          \
	})

/**
 * Minimum heartbeat interval in milliseconds.
 */
#define AS_HB_INTERVAL_MIN 10

/**
 * Size of the network header.
 * Maximum size of IPv4 header - 20 bytes (assuming no variable length fields)
 * Fixed size of IPv6 header - 40 bytes (assuming no extention headers)
 * Maximum size of TCP header - 60 Bytes
 * Size of UDP header (fixed) - 8 bytes
 * So maximum size of empty TCP datagram - 60 + 20 = 80 bytes
 * So maximum size of empty IPv4 UDP datagram - 20 + 8 = 28 bytes
 * Being conservative and assuming 30 bytes for UDP header.
 */
#define UDP_HEADER_SIZE_MAX 30

/**
 * The size of a buffer beyond which compression should be applied. For not set
 * to 60% of the interface mtu.
 */
#define MSG_COMPRESSION_THRESHOLD(mtu) ({ (int)(mtu * 0.6); })

/**
 * Expected ratio - (input size) / (compressed size). Assumming 35% decrease in
 * size after compression.
 */
#define MSG_COMPRESSION_RATIO (1.0 / 0.65)

/**
 * Default allocation size for plugin data.
 */
#define AS_HB_PLUGIN_DATA_DEFAULT_SIZE 128

/**
 * Block size for allocating node plugin data. Ensure the allocation is in
 * multiples of 128 bytes, allowing expansion to 16 nodes without reallocating.
 */
#define HB_PLUGIN_DATA_BLOCK_SIZE 8

/**
 * Global heartbeat instance.
 */
static as_hb g_hb;

/**
 * Global heartbeat events listener instance.
 */
static as_hb_external_events g_hb_event_listeners;

/**
 * Global lock to serialize all read and writes to the heartbeat
 * subsystem.
 */
pthread_mutex_t hb_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/**
 * The big fat lock for all channel state.
 */
pthread_mutex_t channel_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/**
 * The big fat lock for all mesh state.
 */
pthread_mutex_t mesh_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/**
 * The big fat lock for all configuration.
 */
pthread_mutex_t config_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/**
 * The lock used while setting heartbeat protocol.
 */
pthread_mutex_t set_protocol_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/*
 *  Size of the poll events set.
 */
#define POLL_SZ (1024)

/**
 * The default MTU for multicast in case device discovery fails.
 */
#define DEFAULT_MIN_MTU 1500

/**
 * The MTU for underlying network.
 */
#define MTU()                                                                  \
	({                                                                     \
		int mtu = config_override_mtu_get();                           \
		if (!mtu) {                                                    \
			mtu = IS_MESH()                                        \
				? g_hb.mode_state.mesh_state.min_mtu           \
				: g_hb.mode_state.multicast_state.min_mtu;     \
			mtu = mtu > 0 ? mtu : DEFAULT_MIN_MTU;                 \
		}                                                              \
		mtu;                                                           \
	})

/**
 *  Message templates for heart beat messages.
 */
// clang-format off
static msg_template g_hb_msg_template[] = {
	{ AS_HB_MSG_ID, M_FT_UINT32 },
	{ AS_HB_MSG_TYPE, M_FT_UINT32 },
	{ AS_HB_MSG_NODE, M_FT_UINT64 },
	{ AS_HB_MSG_ADDR, M_FT_BUF },
	{ AS_HB_MSG_PORT, M_FT_UINT32 },
	{ AS_HB_MSG_CLUSTER_ID, M_FT_STR },
	{ AS_HB_MSG_HB_DATA, M_FT_BUF },
	{ AS_HB_MSG_MAX_CLUSTER_SIZE, M_FT_UINT32 },
	{ AS_HB_MSG_HLC_TIMESTAMP, M_FT_UINT64 },
	{ AS_HB_MSG_PAXOS_DATA, M_FT_BUF },
	{ AS_HB_MSG_COMPRESSED_PAYLOAD, M_FT_BUF }
};

/**
 * Message scratch size for V3 HB messages. To accomodate 64 node cluster.
 */
#define AS_HB_MSG_SCRATCH_SIZE 1024

static msg_template g_hb_v2_msg_template[] = {
    { AS_HB_MSG_ID, M_FT_UINT32 },
	{ AS_HB_MSG_TYPE, M_FT_UINT32 },
	{ AS_HB_MSG_NODE, M_FT_UINT64 },
	{ AS_HB_MSG_ADDR, M_FT_UINT32 },
	{ AS_HB_MSG_PORT, M_FT_UINT32 },
	{ AS_HB_V2_MSG_ANV, M_FT_BUF },
	{ AS_HB_V2_MSG_ANV_LENGTH, M_FT_UINT32 }
};
// clang-format on

/**
 * Message scratch size for V2 HB messages. To accomodate 64 node cluster.
 */
#define AS_HB_V2_MSG_SCRATCH_SIZE 512

/**
 * The number of bytes for the message length on the wire.
 */
#define MSG_WIRE_LENGTH_SIZE (4)

/**
 * Maximum retries for reading a message.
 */
#define MSG_READ_RETRY_MAX (3)

/**
 * A hard limit on the buffer size for parsing incoming messages.
 */
#define MSG_BUFFER_MAX_SIZE() (10 * 1024 * 1024)

#ifndef ASC
#define ASC (2 << 4)
#endif

/**
 * Maximum memory size allocated on the call stack.
 */
#define STACK_ALLOC_LIMIT() (16 * 1024)

/**
 * Allocate a buffer for heart beat messages. Larger buffers are heap
 * allocated to prevent stack overflows.
 */
#define MSG_BUFF_ALLOC(size)                                                   \
	((size) <= MSG_BUFFER_MAX_SIZE()                                       \
	   ? (((size) > STACK_ALLOC_LIMIT()) ? hb_malloc(size) : alloca(size)) \
	   : NULL)

/**
 * Allocate a buffer for heart beat messages. Larger buffers are heap
 * allocated to prevent stack overflows. Crashes the process on failure to
 * allocate the buffer.
 */
#define MSG_BUFF_ALLOC_OR_DIE(size, crash_msg, ...)                            \
	({                                                                     \
		uint8_t* retval = MSG_BUFF_ALLOC((size));                      \
		if (!retval) {                                                 \
			CRASH(crash_msg, ##__VA_ARGS__);                       \
		}                                                              \
		retval;                                                        \
	})

/**
 * Free the buffer allocated by MSG_BUFF_ALLOC
 */
#define MSG_BUFF_FREE(buffer, size)                                            \
	if (((size) > STACK_ALLOC_LIMIT()) && buffer) {                        \
		hb_free(buffer);                                               \
	}

/**
 * Acquire a lock on the heartbeat main module.
 */
#define HB_LOCK() (pthread_mutex_lock(&hb_lock))

/**
 * Relinquish the lock on the  heartbeat main module.
 */
#define HB_UNLOCK() (pthread_mutex_unlock(&hb_lock))

/**
 * Acquire a lock on the entire channel submodule.
 */
#define CHANNEL_LOCK() (pthread_mutex_lock(&channel_lock))

/**
 * Relinquish the lock on the entire channel submodule.
 */
#define CHANNEL_UNLOCK() (pthread_mutex_unlock(&channel_lock))

/**
 * Keep a winning socket as a winner for at least this amount of time to prevent
 * constant flip flopping and give the winning socket a chance to send heartbeats.
 */
#define CHANNEL_WIN_GRACE_MS() (3 * config_hb_tx_interval_get())

/**
 * Acquire a lock on the entire mesh submodule.
 */
#define MESH_LOCK() (pthread_mutex_lock(&mesh_lock))

/**
 * Relinquish the lock on the entire mesh submodule.
 */
#define MESH_UNLOCK() (pthread_mutex_unlock(&mesh_lock))

/**
 * Acquire a lock on the entire config submodule.
 */
#define CONFIG_LOCK() (pthread_mutex_lock(&config_lock))

/**
 * Relinquish the lock on the entire config submodule.
 */
#define CONFIG_UNLOCK() (pthread_mutex_unlock(&config_lock))

/**
 * Acquire a lock while setting heartbeat protocol dynamically.
 */
#define SET_PROTOCOL_LOCK() (pthread_mutex_lock(&set_protocol_lock))

/**
 * Relinquish the lock after setting heartbeat protocol dynamically.
 */
#define SET_PROTOCOL_UNLOCK() (pthread_mutex_unlock(&set_protocol_lock))

/**
 * Logging macros.
 */
#define CRASH(format, ...) cf_crash(AS_HB, format, ##__VA_ARGS__)
#define WARNING(format, ...) cf_warning(AS_HB, format, ##__VA_ARGS__)
#define INFO(format, ...) cf_info(AS_HB, format, ##__VA_ARGS__)
#define DEBUG(format, ...) cf_debug(AS_HB, format, ##__VA_ARGS__)
#define DETAIL(format, ...) cf_detail(AS_HB, format, ##__VA_ARGS__)
#define ASSERT(expression, message, ...)                                       \
	if (!(expression)) {                                                   \
		WARNING(message, ##__VA_ARGS__);                               \
	}

/*----  Shash related. ----*/

/**
 * Put a key to a hash or crash with an error message on failure.
 */
#define SHASH_PUT_OR_DIE(hash, key, value, error, ...)                         \
	if (SHASH_OK != shash_put(hash, key, value)) {                         \
		CRASH(error, ##__VA_ARGS__);                                   \
	}

/**
 * Delete a key from hash or on failure crash with an error message. Key not
 * found is NOT considered an error.
 */
#define SHASH_DELETE_OR_DIE(hash, key, error, ...)                             \
	if (SHASH_ERR == shash_delete(hash, key)) {                            \
		CRASH(error, ##__VA_ARGS__);                                   \
	}

/**
 * Read value for a key and crash if there is an error. Key not
 * found is NOT considered an error.
 */
#define SHASH_GET_OR_DIE(hash, key, value, error, ...)                         \
	({                                                                     \
		int retval = shash_get(hash, key, value);                      \
		if (retval == SHASH_ERR) {                                     \
			CRASH(error, ##__VA_ARGS__);                           \
		}                                                              \
		retval;                                                        \
	})

/**
 * A soft limit for the maximum cluster size. Meant to be optimize hash and
 * list data structures and not as a limit on the number of nodes.
 */
#define AS_HB_CLUSTER_MAX_SIZE_SOFT 200

/*---- IP address related ----*/

/**
 * Convert ip address to a stack allocated string. Returns a stack allocated
 * buffer with the ip string on success, else NULL.
 */
#define IPADDR_TO_STRING(address_p)                                            \
	({                                                                     \
		char* _endpoint_host_str = alloca(INET6_ADDRSTRLEN);           \
		char* result =                                                 \
		  as_hb_ipaddr_to_string(address_p, _endpoint_host_str);       \
		result;                                                        \
	})

/*---- Timeouts ----*/

/**
 * Connection initiation timeout.
 */
#define CONNECT_TIMEOUT() (config_hb_tx_interval_get() * 3)

/**
 * A channel times out if there is no msg received from a node in this interval.
 * Set to a fraction of node timeout so that a new channel could be set up to
 * recover from a potentially bad connection before the node times out.
 */
#define CHANNEL_NODE_READ_IDLE_TIMEOUT() (2 * AS_HB_NODE_TIMEOUT() / 3)

/**
 * Intervals at which heartbeats are send.
 */
#define PULSE_TRANSMIT_INTERVAL()                                              \
	(MAX(config_hb_tx_interval_get(), AS_HB_INTERVAL_MIN))

/**
 * Intervals at which adjacecny tender runs.
 */
#define ADJACENCY_TEND_INTERVAL() (PULSE_TRANSMIT_INTERVAL())

/**
 * Read write timeout.
 */
#define MESH_RW_TIMEOUT() (config_hb_mesh_rw_retry_timeout_get())

/**
 * Mesh timeout for pending nodes.
 */
#define MESH_PENDING_TIMEOUT() (2 * CONNECT_TIMEOUT())

/**
 * Mesh inactive timeout after which a mesh node will be forgotten.
 */
#define MESH_INACTIVE_TIMEOUT() (10 * AS_HB_NODE_TIMEOUT())

/**
 * Mesh timeout for getting the endpoint for a node after which this node will
 * be forgotten.
 */
#define MESH_ENDPOINT_UNKNOWN_TIMEOUT() (AS_HB_NODE_TIMEOUT())

/**
 * Intervals at which mesh tender runs.
 */
#define MESH_TEND_INTERVAL() (2 * PULSE_TRANSMIT_INTERVAL())

/* Lifespan related */
/**
 * Is channel initialized.
 */
#define CHANNEL_IS_INITIALIZED()                                               \
	({                                                                     \
		CHANNEL_LOCK();                                                \
		bool retval =                                                  \
		  (g_hb.channel_state.status != AS_HB_STATUS_UNINITIALIZED)    \
		    ? true                                                     \
		    : false;                                                   \
		CHANNEL_UNLOCK();                                              \
		retval;                                                        \
	})

/**
 * Is channel running.
 */
#define CHANNEL_IS_RUNNING()                                                   \
	({                                                                     \
		CHANNEL_LOCK();                                                \
		bool retval =                                                  \
		  (g_hb.channel_state.status == AS_HB_STATUS_RUNNING) ? true   \
								      : false; \
		CHANNEL_UNLOCK();                                              \
		retval;                                                        \
	})

/**
 * Is channel stopped.
 */
#define CHANNEL_IS_STOPPED()                                                   \
	({                                                                     \
		CHANNEL_LOCK();                                                \
		bool retval =                                                  \
		  (g_hb.channel_state.status == AS_HB_STATUS_STOPPED) ? true   \
								      : false; \
		CHANNEL_UNLOCK();                                              \
		retval;                                                        \
	})

/**
 * Inidicates if mode is mesh.
 */
#define IS_MESH() (config_mode_get() == AS_HB_MODE_MESH)

/**
 * Is mesh initialized.
 */
#define MESH_IS_INITIALIZED()                                                  \
	({                                                                     \
		MESH_LOCK();                                                   \
		int retval = (g_hb.mode_state.mesh_state.status !=             \
			      AS_HB_STATUS_UNINITIALIZED)                      \
			       ? true                                          \
			       : false;                                        \
		CHANNEL_UNLOCK();                                              \
		retval;                                                        \
	})

/**
 * Is mesh running.
 */
#define MESH_IS_RUNNING()                                                      \
	({                                                                     \
		MESH_LOCK();                                                   \
		int retval =                                                   \
		  (g_hb.mode_state.mesh_state.status == AS_HB_STATUS_RUNNING)  \
		    ? true                                                     \
		    : false;                                                   \
		MESH_UNLOCK();                                                 \
		retval;                                                        \
	})

/**
 * Is mesh running.
 */
#define MESH_IS_STOPPED()                                                      \
	({                                                                     \
		MESH_LOCK();                                                   \
		int retval =                                                   \
		  (g_hb.mode_state.mesh_state.status == AS_HB_STATUS_STOPPED)  \
		    ? true                                                     \
		    : false;                                                   \
		MESH_UNLOCK();                                                 \
		retval;                                                        \
	})

/**
 * Is channel running.
 */
#define CHANNEL_IS_RUNNING()                                                   \
	({                                                                     \
		CHANNEL_LOCK();                                                \
		bool retval =                                                  \
		  (g_hb.channel_state.status == AS_HB_STATUS_RUNNING) ? true   \
								      : false; \
		CHANNEL_UNLOCK();                                              \
		retval;                                                        \
	})

/**
 * Is Main module initialized.
 */
#define HB_IS_INITIALIZED()                                                    \
	({                                                                     \
		HB_LOCK();                                                     \
		bool retval =                                                  \
		  (g_hb.status != AS_HB_STATUS_UNINITIALIZED) ? true : false;  \
		HB_UNLOCK();                                                   \
		retval;                                                        \
	})

/**
 * Is Main module running.
 */
#define HB_IS_RUNNING()                                                        \
	({                                                                     \
		HB_LOCK();                                                     \
		int retval =                                                   \
		  (g_hb.status == AS_HB_STATUS_RUNNING) ? true : false;        \
		HB_UNLOCK();                                                   \
		retval;                                                        \
	})

/**
 * Is Main module stopped.
 */
#define HB_IS_STOPPED()                                                        \
	({                                                                     \
		HB_LOCK();                                                     \
		int retval =                                                   \
		  (g_hb.status == AS_HB_STATUS_STOPPED) ? true : false;        \
		HB_UNLOCK();                                                   \
		retval;                                                        \
	})

/*----------------------------------------------------------------------------
 * Private internal function forward declarations.
 *----------------------------------------------------------------------------*/

static uint32_t as_hb_ipaddr_to_ipv4h(const as_hb_ipaddr* v6_addr);
static uint32_t as_cf_ipaddr_to_ipv4h(const cf_ip_addr* ip_addr);

static void* hb_malloc(size_t size);
static void hb_free(void* buff);
static void config_init();
static cf_node config_self_nodeid_get();
static hb_mode_enum config_mode_get();
static as_hb_ipaddr* config_hb_publish_addr_get();
static int config_hb_publish_port_get();
static as_hb_ipaddr* config_hb_listen_addr_get();
static char* config_hb_listen_addr_s_get();
static char* config_hb_publish_addr_s_get();
static char* config_hb_bind_interface_addr_s_get();
static int config_hb_listen_port_get();
static as_hb_ipaddr* config_hb_bind_interface_addr_get();
static hb_protocol_enum config_protocol_get();
static void config_protocol_set(hb_protocol_enum new_protocol);
static uint32_t config_hb_tx_interval_get();
static void config_hb_tx_interval_set(uint32_t new_interval);
static uint32_t config_hb_max_intervals_missed_get();
static void config_hb_max_intervals_missed_set(uint32_t new_max);
static int config_hb_fabric_grace_factor_get();
static void config_hb_fabric_grace_factor_set(int new_factor);
static uint32_t config_hb_mesh_rw_retry_timeout_get();
static uint32_t config_override_mtu_get();
static void config_override_mtu_set(uint32_t mtu);

static unsigned char config_hb_mcast_ttl_get();

static void channel_dump(bool verbose);
static void channel_clear();

static void mesh_seed_host_list_get(cf_dyn_buf* db);
static void mesh_channel_event_process(as_hb_channel_event* event);
static int mesh_tip(char* host, int port);
static int mesh_tip_clear_reduce(void* key, void* data, void* udata);
static void mesh_clear();

static void multicast_clear();
static int multicast_supported_cluster_size_get();

static msg* hb_info_msg_init(as_hb_msg_type msg_type);
static int hb_adjacent_node_get(cf_node nodeid,
				as_hb_adjacent_node* adjacent_node);
static void hb_dump(bool verbose);
static void hb_channel_event_process(as_hb_channel_event* event);
static msg* hb_msg_get();
static void hb_msg_return(msg* msg);
static void hb_mode_dump(bool verbose);
static void hb_plugin_register(as_hb_plugin* plugin);
static void hb_init();
static void hb_start();
static void hb_stop();
static void hb_clear();
static void hb_adjacent_node_destroy(as_hb_adjacent_node* adjacent_node);
static void hb_maximal_clique_evict(cf_vector* nodes,
				    cf_vector* nodes_to_evict);
static void hb_plugin_data_iterate_all(as_hb_plugin_id pluginid,
				       as_hb_plugin_data_iterate_fn iterate_fn,
				       void* udata);

/*----------------------------------------------------------------------------
 * Public functions.
 *----------------------------------------------------------------------------*/
/**
 * Initialize the heartbeat subsystem.
 */
void
as_hb_init()
{
	// Initialize configuration
	config_init();

	// Initialize hb subsystem.
	hb_init();

	// Add the mesh seed nodes.
	// Using one time seed config outside the config module.
	if (IS_MESH()) {
		for (int i = 0; i < AS_CLUSTER_SZ; i++) {
			if (g_config.hb_config.hb_mesh_seed_addrs[i]) {

				int rv = mesh_tip(
				  g_config.hb_config.hb_mesh_seed_addrs[i],
				  g_config.hb_config.hb_mesh_seed_ports[i]);

				switch (rv) {
					case SHASH_OK:
						INFO("Added mesh seed node "
						     "from config "
						     "%s:%d",
						     g_config.hb_config
						       .hb_mesh_seed_addrs[i],
						     g_config.hb_config
						       .hb_mesh_seed_ports[i]);
						break;
					case SHASH_ERR_FOUND:
						INFO("Duplicate mesh seed node "
						     "from "
						     "config %s:%d",
						     g_config.hb_config
						       .hb_mesh_seed_addrs[i],
						     g_config.hb_config
						       .hb_mesh_seed_ports[i]);
						break;
					case SHASH_ERR:
						WARNING(
						  "Error adding mesh seed node "
						  "from config %s:%d",
						  g_config.hb_config
						    .hb_mesh_seed_addrs[i],
						  g_config.hb_config
						    .hb_mesh_seed_ports[i]);
						break;
				}

			} else {
				break;
			}
		}
	}
}

/**
 * Start the heartbeat subsystem.
 */
void
as_hb_start()
{
	hb_start();
}

/**
 * Shut down the heartbeat subsystem.
 */
void
as_hb_shutdown()
{
	hb_stop();
}

/**
 * Free the data structures of heart beat.
 */
void
as_hb_destroy()
{
	// Destroy the main module.
	hb_clear();
}

/**
 * Return a string representation of a heartbeat protocol type.
 *
 * @param protocol for which the string is computed
 * @param protocol_s string representation of protocol
 */
void
as_hb_protocol_get_s(hb_protocol_enum protocol, char* protocol_s)
{
	sprintf(protocol_s, "%s",
		(AS_HB_PROTOCOL_V1 == protocol
		   ? "v1"
		   : (AS_HB_PROTOCOL_V2 == protocol
			? "v2"
			: (AS_HB_PROTOCOL_V3 == protocol
			     ? "v3"
			     : (AS_HB_PROTOCOL_NONE == protocol
				  ? "none"
				  : (AS_HB_PROTOCOL_RESET == protocol
				       ? "reset"
				       : "undefined"))))));
}

/**
 * Set heartbeat protocol version.
 */
int
as_hb_set_protocol(hb_protocol_enum protocol)
{
	SET_PROTOCOL_LOCK();
	int rv = 0;
	if (config_protocol_get() == protocol) {
		INFO("no heartbeat protocol change needed");
		rv = 0;
		goto Exit;
	}
	char protocol_s[AS_HB_PROTOCOL_STR_MAX_LEN()];
	switch (protocol) {
		case AS_HB_PROTOCOL_V1:
		case AS_HB_PROTOCOL_V2:
		case AS_HB_PROTOCOL_V3:
			if (HB_IS_RUNNING()) {
				as_hb_protocol_get_s(config_protocol_get(),
						     protocol_s);
				INFO("Disabling current "
				     "heatbeat protocol %s",
				     protocol_s);
				hb_stop();
			}
			as_hb_protocol_get_s(protocol, protocol_s);
			INFO("Setting heartbeat protocol version number to %s",
			     protocol_s);
			config_protocol_set(protocol);
			hb_start();
			INFO("Heartbeat protocol version set to %s",
			     protocol_s);

			break;

		case AS_HB_PROTOCOL_NONE:
			INFO("Setting heartbeat protocol version to none");
			hb_stop();
			config_protocol_set(protocol);
			INFO("Heartbeat protocol set to none");
			break;

		case AS_HB_PROTOCOL_RESET:
			if (AS_HB_PROTOCOL_NONE == config_protocol_get()) {
				INFO("Heartbeat messaging disabled "
				     "~~ not resetting");
				rv = -1;
				goto Exit;
			}

			// NB: "hb_protocol" is never actually set to "RESET" ~~
			// it is simply a trigger for the reset action.
			INFO("Resetting heartbeat messaging");
			as_hb_protocol_get_s(config_protocol_get(), protocol_s);
			INFO("Disabling current heatbeat protocol (%s)",
			     protocol_s);

			hb_stop();

			hb_clear();

			hb_start();

			break;

		default:
			WARNING("Unknown heartbeat protocol version number: %d",
				protocol);
			rv = -1;
			goto Exit;
	}

Exit:
	SET_PROTOCOL_UNLOCK();
	return rv;
}

/**
 * Register a heartbeat plugin.
 */
void
as_hb_plugin_register(as_hb_plugin* plugin)
{
	if (!HB_IS_INITIALIZED()) {
		WARNING("Main heartbeat module unintialized. Not registering "
			"the plugin.");
		return;
	}
	hb_plugin_register(plugin);
}

/**
 * Get the ip address of a node given its node id.
 *
 * @param node the node to get ip address of.
 * @param addr the output ip address on success, undefined on failure.
 *
 * @return 0 if the node's ip adddress is found. -1 on failure.
 */
int
as_hb_getaddr(cf_node nodeid, cf_ip_addr* ip_addr)
{
	int rv = -1;
	if (!HB_IS_INITIALIZED()) {
		WARNING(
		  "Main heartbeat module unintialized. Address not found.");
		return rv;
	}

	HB_LOCK();
	as_hb_adjacent_node node;
	if (SHASH_OK == shash_get(g_hb.adjacency, &nodeid, &node)) {

		rv = cf_ip_addr_from_binary((uint8_t*)&node.addr,
					    sizeof(node.addr), ip_addr) >= 0
		       ? 0
		       : -1;
	} else {
		rv = -1;
	}
	HB_UNLOCK();

	return rv;
}

/**
 * Register a heartbeat node event listener.
 */
void
as_hb_register_listener(as_hb_event_fn event_callback, void* udata)
{
	if (!HB_IS_INITIALIZED()) {
		WARNING("Main heartbeat module unintialized. Not registering "
			"the listner.");
		return;
	}

	HB_LOCK();

	if (g_hb_event_listeners.event_listener_count >=
	    AS_HB_EVENT_LISTENER_MAX) {
		CRASH("Cannot register more than %d event "
		      "listeners.",
		      AS_HB_EVENT_LISTENER_MAX);
	}

	g_hb_event_listeners
	  .event_listeners[g_hb_event_listeners.event_listener_count]
	  .event_callback = event_callback;
	g_hb_event_listeners
	  .event_listeners[g_hb_event_listeners.event_listener_count]
	  .udata = udata;
	g_hb_event_listeners.event_listener_count++;

	HB_UNLOCK();
}

/**
 * Validate heartbeat config.
 */
void
as_hb_config_validate()
{
	if (config_hb_listen_port_get() == 0) {
		CRASH("Invalid %s listening port %d",
		      (IS_MESH()) ? "MESH" : "MULTICAST",
		      config_hb_listen_port_get());
	}
	if (!IS_MESH() && g_config.hb_config.hb_mesh_seed_addrs[0]) {
		CRASH("Invalid config option. mesh-seed-address-port not "
		      "supported for multicast mode.");
	}
}

/**
 * Override the computed MTU for the network interface used by heartbeat.
 */
void
as_hb_override_mtu_set(int mtu)
{
	config_override_mtu_set(mtu);
}

/**
 * Get the heartbeat pulse transmit interval.
 */
uint32_t
as_hb_tx_interval_get()
{
	return config_hb_tx_interval_get();
}

/**
 * Set the heartbeat pulse transmit interval.
 */
void
as_hb_tx_interval_set(uint32_t new_interval)
{
	config_hb_tx_interval_set(new_interval);
}

/**
 * Set the maximum number of missed heartbeat intervals after which a node is
 * considered expired.
 */
void
as_hb_max_intervals_missed_set(uint32_t new_max)
{
	config_hb_max_intervals_missed_set(new_max);
}

/**
 * Set multiple of 'hb max intervals missed' during which if no fabric messages
 * arrive from a node, the node is considered fabric expired. Set to -1 for
 * infinite grace period.
 */
void
as_hb_fabric_grace_factor_set(int new_max)
{
	config_hb_fabric_grace_factor_set(new_max);
}

/**
 * Get the timeout interval to consider a node dead / expired in milliseconds if
 * no heartbeat pulse messages are received.
 */
uint32_t
as_hb_node_timeout_get()
{
	return AS_HB_NODE_TIMEOUT();
}

/**
 * Populate the buffer with heartbeat configuration.
 */
void
as_hb_info_config_get(cf_dyn_buf* db)
{
	info_append_string(db, "heartbeat.mode",
			   IS_MESH() ? "mesh" : "multicast");
	info_append_string(db, "heartbeat.address",
			   config_hb_listen_addr_s_get());
	info_append_int(db, "heartbeat.port", config_hb_listen_port_get());

	if (IS_MESH()) {
		mesh_seed_host_list_get(db);
	}

	info_append_uint32(db, "heartbeat.interval",
			   config_hb_tx_interval_get());
	info_append_uint32(db, "heartbeat.timeout",
			   config_hb_max_intervals_missed_get());

	info_append_int(db, "heartbeat.fabric-grace-factor",
			config_hb_fabric_grace_factor_get());
	info_append_string(
	  db, "heartbeat.interface-address",
	  config_hb_bind_interface_addr_s_get()); // TODO - empty string ok?
	info_append_uint32(db, "heartbeat.mcast-ttl",
			   config_hb_mcast_ttl_get());
	info_append_uint32(db, "heartbeat.mesh-rw-retry-timeout",
			   config_hb_mesh_rw_retry_timeout_get());
	info_append_int(db, "heartbeat.mtu", MTU());

	char protocol_s[AS_HB_PROTOCOL_STR_MAX_LEN()];
	as_hb_protocol_get_s(config_protocol_get(), protocol_s);

	info_append_string(db, "heartbeat.protocol", protocol_s);
}

/**
 * Generate a string for listening address and port in format ip_address:port
 * and return the heartbeat mode.
 *
 * @param mode (output) current heartbeat subsystem mode.
 * @param addr_port (output) listening ip address and port formatted as
 * ip_address:port
 */
void
as_hb_info_listen_addr_get(hb_mode_enum* mode, char* addr_port)
{
	*mode = IS_MESH() ? AS_HB_MODE_MESH : AS_HB_MODE_MCAST;
	sprintf(addr_port, "%s:%d", config_hb_listen_addr_s_get(),
		config_hb_listen_port_get());
}

/**
 * Inidcates if the input max cluster size is valid based on hb state.Transient
 * API to help with deciding to apply new max cluster size.
 */
bool
as_hb_max_cluster_size_isvalid(uint32_t max_cluster_size)
{
	HB_LOCK();
	// Self node is skipped in adjacency list. add one for validation.

	uint32_t adjacency_size = shash_get_size(g_hb.adjacency) + 1;

	bool isvalid = max_cluster_size >= adjacency_size;
	if (!isvalid) {
		WARNING("Rejected new max cluster size %d which is less than "
			"or equal to adjacency size %d.",
			max_cluster_size, adjacency_size);
	}
	HB_UNLOCK();
	return isvalid;
}

/*-----------------------------------------------------------------
 * Mesh mode public API
 *-----------------------------------------------------------------*/
/**
 * Add an aerospike instance from the mesh seed list.
 */
int
as_hb_mesh_tip(char* host, int port)
{
	if (!IS_MESH()) {
		WARNING("Tip not applicable for multicast.");
		return (-1);
	}

	return mesh_tip(host, port);
}

/**
 * Remove an aerospike seed entry from the mesh seed list.
 */
int
as_hb_mesh_tip_clear(char* host, int port)
{
	if (!IS_MESH()) {
		WARNING("Tip clear not applicable for multicast.");
		return (-1);
	}

	if (host == NULL || host[0] == '\0' ||
	    strnlen(host, HOST_NAME_MAX) == HOST_NAME_MAX) {
		WARNING("Incorrect host or port");
		return (-1);
	}

	MESH_LOCK();

	as_hb_mesh_tip_clear_udata mesh_tip_clear_reduce_udata;
	strncpy(mesh_tip_clear_reduce_udata.host, host, HOST_NAME_MAX);
	mesh_tip_clear_reduce_udata.port = port;
	shash_reduce_delete(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			    mesh_tip_clear_reduce,
			    &mesh_tip_clear_reduce_udata);

	MESH_UNLOCK();
	return (0);
}

/**
 * Forget all the seed nodes.
 */
int
as_hb_mesh_tip_clear_all()
{
	if (!IS_MESH()) {
		WARNING("Tip clear not applicable for multicast.");
		return (-1);
	}

	MESH_LOCK();
	as_hb_mesh_tip_clear_udata mesh_tip_clear_reduce_udata;
	mesh_tip_clear_reduce_udata.host[0] = '\0';
	shash_reduce_delete(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			    mesh_tip_clear_reduce,
			    &mesh_tip_clear_reduce_udata);
	MESH_UNLOCK();
	return (0);
}

/**
 * Read the plugin data for a node in the adjacency list. The plugin data is
 * always heap allocated and if not NULL should be freed using cf_free.
 *
 * @param nodeid the node id
 * @param pluginid the plugin identifier.
 * @param plugin_data (output) a double pointer to the saved plugin data for the
 * node. NULL if there is no plugin data.
 * @praram msg_hlc_ts  (output) if not NULL will be filled with the timestamp of
 * when the hb message for this data was received.
 * @param recv_monotonic_ts (output) if not NULL will be filled with monotonic
 * wall clock receive timestamp for this plugin data.
 * @return the size of the plugin data. 0 if there is no plugin data.
 */
int
as_hb_plugin_data_get(cf_node nodeid, as_hb_plugin_id plugin,
		      void** plugin_data, as_hlc_msg_timestamp* msg_hlc_ts,
		      cf_clock* recv_monotonic_ts)
{
	int rv = 0;
	*plugin_data = NULL;
	HB_LOCK();

	as_hb_adjacent_node adjacent_node;
	if (hb_adjacent_node_get(nodeid, &adjacent_node) != 0) {
		*plugin_data = NULL;
		rv = 0;
		goto Exit;
	}

	as_hb_plugin_node_data* plugin_data_internal =
	  &adjacent_node
	     .plugin_data[plugin][adjacent_node.plugin_data_cycler % 2];

	if (plugin_data_internal->data && plugin_data_internal->data_size) {
		*plugin_data = cf_malloc(plugin_data_internal->data_size);
		if (!*plugin_data) {
			CRASH("Error allocating space for plugin data copy.");
		}

		// Set the plugin data size
		rv = plugin_data_internal->data_size;

		// Copy over the stored copy of the plugin data.
		memcpy(*plugin_data, plugin_data_internal->data, rv);

		// Copy the message timestamp.
		if (msg_hlc_ts) {
			memcpy(msg_hlc_ts, &adjacent_node.last_msg_hlc_ts,
			       sizeof(as_hlc_msg_timestamp));
		}

		if (recv_monotonic_ts) {
			*recv_monotonic_ts =
			  adjacent_node.lasted_updated_monotonic_ts;
		}
	} else {
		// No plugin data set.
		*plugin_data = NULL;
		if (recv_monotonic_ts) {
			*recv_monotonic_ts = 0;
		}
		if (msg_hlc_ts) {
			memset(msg_hlc_ts, 0, sizeof(as_hlc_msg_timestamp));
		}
		rv = 0;
	}

Exit:
	HB_UNLOCK();
	return rv;
}

/**
 * Call the iterate method on plugin data for all nodes in the input vector. The
 * iterate function will be invoked for all nodes in the input vector even if
 * they are not in the adjacency list of have no plugin data. Plugin data will
 * be NULL with size zero in such cases.
 *
 * @param nodes the iterate on.
 * @param plugin the plugin identifier.
 * @param iterate_fn the iterate function invoked for plugin data for every
 * node.
 * @param udata passed as is to the iterqte function. Useful for getting results
 * out of the iteration.
 * NULL if there is no plugin data.
 * @return the size of the plugin data. 0 if there is no plugin data.
 */
void
as_hb_plugin_data_iterate(cf_vector* nodes, as_hb_plugin_id plugin,
			  as_hb_plugin_data_iterate_fn iterate_fn, void* udata)

{
	HB_LOCK();

	int size = cf_vector_size(nodes);

	for (int i = 0; i < size; i++) {
		cf_node* nodeid = cf_vector_getp(nodes, i);

		if (nodeid == NULL || *nodeid == 0) {
			continue;
		}

		as_hb_adjacent_node nodeinfo;

		size_t data_size =
		  nodeinfo.plugin_data[plugin][nodeinfo.plugin_data_cycler % 2]
		    .data_size;
		void* data =
		  data_size
		    ? nodeinfo
			.plugin_data[plugin][nodeinfo.plugin_data_cycler % 2]
			.data
		    : NULL;

		if (hb_adjacent_node_get(*nodeid, &nodeinfo) == 0) {
			iterate_fn(*nodeid, data, data_size,
				   nodeinfo.lasted_updated_monotonic_ts,
				   &nodeinfo.last_msg_hlc_ts, udata);
		} else {
			// This node is not known to the heartbeat subsystem.
			iterate_fn(*nodeid, NULL, 0, 0, NULL, udata);
		}
	}

	HB_UNLOCK();
}

/**
 * Call the iterate method on all nodes in current adjacency list. Note plugin
 * data can still be NULL if the plugin data failed to parse the plugin data.
 *
 * @param pluginid the plugin identifier.
 * @param iterate_fn the iterate function invoked for plugin data for every
 * node.
 * @param udata passed as is to the iterqte function. Useful for getting results
 * out of the iteration.
 * NULL if there is no plugin data.
 * @return the size of the plugin data. 0 if there is no plugin data.
 */
void
as_hb_plugin_data_iterate_all(as_hb_plugin_id pluginid,
			      as_hb_plugin_data_iterate_fn iterate_fn,
			      void* udata)
{
	hb_plugin_data_iterate_all(pluginid, iterate_fn, udata);
}

/**
 * Return a string summarizing the number of heartbeat-related errors of each
 * type.
 * @param verbose use long format messages if "verbose" is true, otherwise use
 * short format messages.
 * @return NULL terminated string containing the stats.
 */
char*
as_hb_stats_get(bool verbose)
{
	static char g_line[1024];

	char msg[sizeof(g_line) / AS_HB_ERR_MAX_TYPE];
	int pos = 0;
	g_line[pos] = '\0';

	for (int i = 0; i < AS_HB_ERR_MAX_TYPE; i++) {
		msg[0] = '\0';
		snprintf(
		  msg, sizeof(msg), "%s %lu ",
		  as_hb_error_msg[i][verbose ? LONG_FORMAT : SHORT_FORMAT],
		  as_hb_error_count[i]);
		// Ensure NULL termination.
		msg[sizeof(msg) - 1] = 0;
		strncat(g_line, msg, sizeof(msg));
	}

	return g_line;
}

/**
 *  Log the state of the heartbeat module.
 */
void
as_hb_dump(bool verbose)
{
	INFO("Heartbeat Dump:");

	// Dump the config.
	INFO("HB Mode:  %s (%d)",
	     (!IS_MESH() ? "multicast" : (IS_MESH() ? "mesh" : "undefined")),
	     config_mode_get());

	INFO("HB Addr:  %s", config_hb_listen_addr_s_get());
	INFO("HB Port:  %d", config_hb_listen_port_get());
	INFO("HB MTU:  %d", MTU());

	INFO("HB Publish Addr:  %s", config_hb_publish_addr_s_get());

	INFO("HB Interval:  %d", config_hb_tx_interval_get());
	INFO("HB Timeout:  %d", config_hb_max_intervals_missed_get());
	INFO("HB Fabric Grace Factor:  %d",
	     config_hb_fabric_grace_factor_get());
	char protocol_s[AS_HB_PROTOCOL_STR_MAX_LEN()];
	as_hb_protocol_get_s(config_protocol_get(), protocol_s);
	INFO("HB Protocol:  %s (%d)", protocol_s, config_protocol_get());

	// dump mode specific state.
	hb_mode_dump(verbose);

	// Dump the channel state.
	channel_dump(verbose);

	// Dump the adjacency list.
	hb_dump(verbose);
}

/**
 * Indicates if a node is alive.
 */
bool
as_hb_is_alive(cf_node nodeid)
{
	bool is_alive = false;
	HB_LOCK();

	as_hb_adjacent_node adjacent_node;
	is_alive = (nodeid == config_self_nodeid_get()) ||
		   (hb_adjacent_node_get(nodeid, &adjacent_node) == 0);

	HB_UNLOCK();
	return is_alive;
}

/**
 * Reduce function to find nodes that have are not in a succession list, but
 * part of the adjacency list.
 */
static int
hb_new_nodes_find_reduce(void* key, void* data, void* udata)
{

	as_hb_find_new_nodes_reduce_udata* u =
	  (as_hb_find_new_nodes_reduce_udata*)udata;
	cf_node nodeid = *(cf_node*)key;

	bool is_new_node = true;

	// Get a list of expired nodes.
	for (int i = 0; i < u->succession_size; i++) {
		if (u->succession[i] == nodeid) {
			is_new_node = false;
		}
	}

	if (is_new_node && u->event_count < u->max_events) {
		memset(&u->events[u->event_count], 0, sizeof(as_hb_event_node));
		u->events[u->event_count].evt = AS_HB_NODE_ARRIVE;
		u->events[u->event_count].nodeid = nodeid;
		u->events[u->event_count].event_time =
		  u->events[u->event_count].event_detected_time = cf_getms();
		INFO("Marking node add for paxos recovery: %" PRIx64,
		     u->events[u->event_count].nodeid);
		u->event_count++;
	}

	return SHASH_OK;
}

/**
 * Generate events required to transform the input succession list to a list
 * that would be consistent with the heart beat adjacency list. This means nodes
 * that are in the adjacency list but missing from the succession list will
 * generate an NODE_ARRIVE event. Nodes in the succession list but missing from
 * the adjacency list will generate a NODE_DEPART event.
 *
 * @param succession the succession list to correct. This should be large
 * enough to hold g_config.paxos_max_cluster_size events.
 * @param succcession_size the size of the succession list.
 * @param events the output events. This should be large enough to hold
 * g_config.paxos_max_cluster_size events.
 * @param max_events the maximum number of events to generate, should be the
 * allocated size of events array.
 * @return the number of corrective events generated.
 */
int
as_hb_get_corrective_events(cf_node* succession, size_t succession_size,
			    as_hb_event_node* events, size_t max_events)
{

	// current event count;
	int event_count = 0;

	// Mark expired nodes that are present in the succession list.
	for (int i = 0; i < succession_size && event_count < max_events; i++) {

		if (succession[i] == 0) {
			break;
		}

		// Check if the node is alive.
		if (!as_hb_is_alive(succession[i])) {
			memset(&events[event_count], 0,
			       sizeof(as_hb_event_node));
			events[event_count].evt = AS_HB_NODE_DEPART;
			events[event_count].nodeid = succession[i];
			// We do not know at what time the node actually
			// departed. Assume we detected the departure right now.
			events[event_count].event_detected_time = cf_getms();
			events[event_count].event_time = NODE_DEPART_TIME(
			  events[event_count].event_detected_time);

			INFO(
			  "Marking node removal for paxos recovery: %" PRIx64,
			  events[event_count].nodeid);
			event_count++;
		}
	}

	// Generate events for nodes that should be added to the succession
	// list.
	as_hb_find_new_nodes_reduce_udata udata;
	memset(&udata, 0, sizeof(udata));
	udata.event_count = event_count;
	udata.events = events;
	udata.succession = succession;
	udata.succession_size = succession_size;
	udata.max_events = max_events;

	HB_LOCK();
	shash_reduce(g_hb.adjacency, hb_new_nodes_find_reduce, &udata);
	HB_UNLOCK();

	return udata.event_count;
}

/**
 * Compute the nodes to evict from the input nodes so that remaining nodes form
 * a clique, based on adjacency lists. Self nodeid is never considered for
 * eviction.
 *
 * @param nodes input cf_node vector.
 * @param nodes_to_evict output cf_node clique array, that is initialized.
 */
void
as_hb_maximal_clique_evict(cf_vector* nodes, cf_vector* nodes_to_evict)
{
	hb_maximal_clique_evict(nodes, nodes_to_evict);
}

/*----------------------------------------------------------------------------
 * Common submodule.
 *----------------------------------------------------------------------------*/

/* ---- Utility ---- */

/**
 * Indirection to cf_malloc. ASM instrumentation in CPPMallocations fails if the
 * malloc call is not on separate line. Macro preprocessor does not preserve
 * newlines.
 */
static void*
hb_malloc(size_t size)
{
	return cf_malloc(size);
}

/**
 * Indirection to cf_free. ASM instrumentation in CPPMallocations fails if the
 * free call is not on separate line. Macro preprocessor does not preserve
 * newlines.
 */
static void
hb_free(void* buff)
{
	cf_free(buff);
}

/**
 * Round up input int to the nearest power of two.
 */
static uint32_t
round_up_pow2(uint32_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

/**
 * Generate a hash code for a blob using Jenkins hash function.
 */
static uint32_t
as_hb_blob_hash(uint8_t* value, size_t value_size)
{

	uint32_t hash = 0;
	for (int i = 0; i < value_size; ++i) {
		hash += value[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

/**
 * Generate a hash code for as_hb_endpoint.
 */
static uint32_t
as_hb_mesh_node_key_hash_fn(void* value)
{
	// Note packed structure ensures a generic blob hash function works
	// well.
	return as_hb_blob_hash((uint8_t*)value, sizeof(as_hb_mesh_node_key));
}

/**
 * Generate a hash code for a cf_socket.
 */
static uint32_t
as_hb_socket_hash_fn(void* value)
{
	cf_socket** socket = (cf_socket**)value;
	return as_hb_blob_hash((uint8_t*)socket, sizeof(cf_socket*));
}

/**
 * Reduce function to delete all emtries in a map
 */
static int
as_hb_delete_all_reduce(void* key, void* data, void* udata)
{
	return SHASH_REDUCE_DELETE;
}

/* ---- Vector operations ---- */
/**
 * TODO: Move this to cf_vector.
 * Find the index of an element in the vector. Equality is based on mem compare.
 *
 * @param vector the source vector.
 * @param element the element to find.
 * @return the index if the element is found, -1 otherwise.
 */
static int
vector_find(cf_vector* vector, void* element)
{
	int element_count = cf_vector_size(vector);
	size_t value_len = vector->value_len;
	for (int i = 0; i < element_count; i++) {
		// No null check required since we are iterating under a lock
		// and within vector bounds.
		void* src_element = cf_vector_getp(vector, i);
		if (src_element) {
			if (memcmp(element, src_element, value_len) == 0) {
				return i;
			}
		}
	}
	return -1;
}

/* ---- Stats ---- */

/**
 * Increment the occurrence count for a heartbeat-related error of the given
 * type.
 */
static void
stats_error_count(as_hb_err_type type)
{
	if ((0 <= type) && (type <= AS_HB_ERR_MAX_TYPE)) {
		cf_atomic_int_incr(&as_hb_error_count[type]);
	}
}

/*---- IP address related ----*/
/**
 * Compare two ip addresses.
 *
 * @param addr1 the first address.
 * @param addr2 the second address.
 * @return same as those of memcmp.
 */
static int
as_hb_ipaddr_cmp(const as_hb_ipaddr* addr1, const as_hb_ipaddr* addr2)
{
	return memcmp(addr1, addr2, sizeof(*addr1));
}

/**
 * Indicates if an ip address is specified.
 * @param addr source  address.
 * @return true if the address is specified, false if the address is not
 * specified.
 */
static bool
as_hb_ipaddr_is_specified(const as_hb_ipaddr* addr)
{
	static const as_hb_ipaddr null_addr = {
		.addr.word =
		  {
		    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		  },
	};
	return as_hb_ipaddr_cmp(&null_addr, addr) != 0;
}

/**
 * Convert a network ordered IPv4 address to an IPv6 address as IPv4-mapped IPv6
 * address.
 * @param v4_addr source ipv4 address in network order.
 * @param v6_addr destination ipv6 address.
 */
static void
as_hb_ipaddr_from_ipv4(uint32_t v4_addr, as_hb_ipaddr* v6_addr)
{
	static const as_hb_ipaddr v4_to_v6_template = {
		.addr.word =
		  {
		    0x0, 0x0, 0x0, 0x0, 0x0, 0xffff, 0x0, 0x0,
		  },
	};
	v6_addr->addr.qword[0] = v4_to_v6_template.addr.qword[0];
	v6_addr->addr.qword[1] = v4_to_v6_template.addr.qword[1];
	v6_addr->addr.dword[3] = v4_addr;
}

/**
 * Convert an as_hb_ipaddr to network ordered ipv4 address.
 * @param v6_addr v6 address in network order.
 */
static uint32_t
as_hb_ipaddr_to_ipv4h(const as_hb_ipaddr* v6_addr)
{
	return v6_addr->addr.dword[3];
}

/**
 * Convert an as_hb_ipaddr to network ordered ipv4 address.
 * @param v4_addr ipv4 address in network order.
 * @param v ipv6 address.
 */
static uint32_t
as_cf_ipaddr_to_ipv4h(const cf_ip_addr* ip_addr)
{
	return ip_addr->s_addr;
}

/**
 * Convert a as_hb_ipaddr to a human readable string.
 *
 * TODO: For now sticking to ipv4 formatted string. Should change once we move
 * completely over to ipv6.
 *
 * @param addr the ip address.
 * @param dest the destination character array. Should have a capacity of at
 * least INET6_ADDRSTRLEN
 * @return dest on success, NULL on failure in conversion.
 */
static char*
as_hb_ipaddr_to_string(const as_hb_ipaddr* addr, char* dest)
{
	uint32_t ipv4_addr = as_hb_ipaddr_to_ipv4h(addr);
	if (inet_ntop(AF_INET, &ipv4_addr, dest, INET6_ADDRSTRLEN) != NULL) {
		return dest;
	}
	return NULL;
}

/**
 * Compare two endpoints
 *
 * @param endpoint1 the first endpoint.
 * @param endpoint2 the second endpoint.
 * @return same as those of memcmp.
 */
static int
as_hb_endpoint_cmp(const as_hb_endpoint* endpoint1,
		   const as_hb_endpoint* endpoint2)
{
	return memcmp(endpoint1, endpoint2, sizeof(*endpoint1));
}

/**
 * Indicates if an endpoint is specified.
 * @param endpoint source  endpoint.
 * @return true if the endpoint is specified, false if the endpoint is not
 * specified.
 */
static bool
as_hb_endpoint_is_specified(const as_hb_endpoint* endpoint)
{
	return as_hb_ipaddr_is_specified(&endpoint->addr) && endpoint->port > 0;
}

/*---- Message related ----*/

/**
 * Read an endpoint from an incoming message.
 * @param msg the incoming message.
 * @param endpoint the output endpoint.
 * @return 0 on success -1 on failure.
 */
static int
msg_endpoint_get(msg* msg, as_hb_endpoint* endpoint)
{
	uint32_t port;
	if (!HB_IS_MSG_LEGACY(msg)) {
		uint8_t* addr_p = NULL;
		size_t address_length = 0;
		if (msg_get_buf(msg, AS_HB_MSG_ADDR, &addr_p, &address_length,
				MSG_GET_DIRECT) != 0 ||
		    address_length != sizeof(as_hb_ipaddr)) {
			WARNING("Error reading ip address form message.");
			return -1;
		}

		memcpy(&endpoint->addr, addr_p, address_length);
	} else {
		uint32_t addr_temp;
		if (msg_get_uint32(msg, AS_HB_MSG_ADDR, &addr_temp) != 0) {
			WARNING("Error reading ip address form message.");
			return -1;
		}
		// v2 sends addresses in network order over the wire.
		as_hb_ipaddr_from_ipv4(addr_temp, &endpoint->addr);
	}

	if (msg_get_uint32(msg, AS_HB_MSG_PORT, &port) != 0) {
		WARNING("Error reading port form message.");
		return -1;
	}

	endpoint->port = port;

	return 0;
}

/**
 * Read the protocol identifier for this heartbeat message. These functions can
 * get called multiple times for a single message. Hence they do not increment
 * error counters.
 * @param msg the incoming message.
 * @param id the output id.
 * @return 0 if the id could be parsed -1 on failure.
 */
static int
msg_id_get(msg* msg, uint32_t* id)
{
	if (msg_get_uint32(msg, AS_HB_MSG_ID, id) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Read the max cluster size from the incoming message.
 * @param msg the incoming message.
 * @param max_cluster_size the output max cluster size.
 * @return 0 if the max cluster size could be parsed -1 on failure.
 */
static int
msg_max_cluster_size_get(msg* msg, uint32_t* max_cluster_size)
{
	if (msg_get_uint32(msg, AS_HB_MSG_MAX_CLUSTER_SIZE, max_cluster_size) !=
	    0) {
		return -1;
	}
	return 0;
}

/**
 * Read the source nodeid for a node. These functions can get called multiple
 * times for a single message. Hence they do not increment error counters.
 * @param msg the incoming message.
 * @param nodeid the output nodeid.
 * @return 0 if the nodeid could be parsed -1 on failure.
 */
static int
msg_nodeid_get(msg* msg, cf_node* nodeid)
{
	if (msg_get_uint64(msg, AS_HB_MSG_NODE, nodeid) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Read the HLC send timestamp for the message. These functions can get called
 * multiple times for a single message. Hence they do not increment error
 * counters.
 * @param msg the incoming message.
 * @param send_ts the output hls timestamp.
 * @return 0 if the time stamp could be parsed -1 on failure.
 */
static int
msg_send_ts_get(msg* msg, as_hlc_timestamp* send_ts)
{
	if (HB_IS_MSG_LEGACY(msg)) {
		// Fake a send timestamp. Legacy does not send timestamps.
		*send_ts =
		  as_hlc_timestamp_substract_ms(as_hlc_timestamp_now(), 1);
		return 0;
	}

	if (msg_get_uint64(msg, AS_HB_MSG_HLC_TIMESTAMP, send_ts) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Read the message type.  These functions can get called multiple times for a
 * single message. Hence they do not increment error counters.
 * @param msg the incoming message.
 * @param type the output message type.
 * @return 0 if the type could be parsed -1 on failure.
 */
static int
msg_type_get(msg* msg, as_hb_msg_type* type)
{
	if (msg_get_uint32(msg, AS_HB_MSG_TYPE, type) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Read the cluster id.
 * @param msg the incoming message.
 * @param cluster id of the output message type.
 * @return 0 if the cluster id could be parsed -1 on failure.
 */
static int
msg_cluster_id_get(msg* msg, char** cluster_id)
{

	if (msg_get_str(msg, AS_HB_MSG_CLUSTER_ID, cluster_id, NULL,
			MSG_GET_DIRECT) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Get a pointer to the adjacency list in the message.
 *
 * @param msg the incoming message.
 * @param adj_list output. on success will point to the adjacency list in the
 * message.
 * @para adj_length output. on success will contain the length of the adjacency
 * list.
 * @return 0 on success. -1 if the adjacency list is absent.
 */
static int
msg_adjacency_get(msg* msg, cf_node** adj_list, size_t* adj_length)
{
	int data_index =
	  HB_IS_MSG_LEGACY(msg) ? AS_HB_V2_MSG_ANV : AS_HB_MSG_HB_DATA;

	if (msg_get_buf(msg, data_index, (uint8_t**)adj_list, adj_length,
			MSG_GET_DIRECT) != 0) {
		return -1;
	}

	// correct adjacency list length.
	*adj_length /= sizeof(cf_node);

	// Compute the filled adjacency list length for version V2.
	if (HB_IS_MSG_LEGACY(msg)) {
		size_t trunc_adj_length = 0;
		for (int i = 0; i < *adj_length; i++) {
			if ((*adj_list)[i] == 0) {
				break;
			}
			trunc_adj_length++;
		}

		*adj_length = trunc_adj_length;
	}

	return 0;
}

/**
 * Set the adjacency list on an outgoing messages.
 *
 * @param msg the outgoing message.
 * @param adj_list the adjacency list to set.
 * @para adj_length the length of the adjacecny list.
 */
static void
msg_adjacency_set(msg* msg, cf_node* adj_list, size_t adj_length)
{

	if (msg_set_buf(msg, AS_HB_MSG_HB_DATA, (uint8_t*)adj_list,
			sizeof(cf_node) * adj_length, MSG_SET_COPY) != 0) {
		CRASH("Error setting adjacency list on msg.");
	}

	return;
}

/**
 * Set the info reply on an outgoing messages.
 *
 * @param msg the outgoing message.
 * @param response the response list to set.
 * @para response_count the length of the response list.
 */
static void
msg_info_reply_set(msg* msg, as_hb_mesh_info_reply* response,
		   size_t response_count)
{
	if (HB_IS_MSG_LEGACY(msg)) {
		// heartbeat versions V2 and V1 send info replies embedded in
		// the header.
		if (msg_set_uint64(msg, AS_HB_MSG_NODE, response[0].nodeid) !=
		    0) {
			CRASH("Error setting ip address for info reply.");
		}

		if (msg_set_uint32(
		      msg, AS_HB_MSG_ADDR,
		      as_hb_ipaddr_to_ipv4h(&response[0].endpoint.addr)) != 0) {
			CRASH("Error setting ip address for info reply.");
		}

		if (msg_set_uint32(msg, AS_HB_MSG_PORT,
				   response[0].endpoint.port) != 0) {
			CRASH("Error setting ip port for info reply.");
		}

	} else {
		if (msg_set_buf(msg, AS_HB_MSG_HB_DATA, (uint8_t*)response,
				sizeof(as_hb_mesh_info_reply) * response_count,
				MSG_SET_COPY) != 0) {
			CRASH("Error setting info reply on msg.");
		}
	}

	return;
}

/**
 * Get a pointer to the info reply list in the message.
 *
 * @param msg the incoming message.
 * @param reply output. on success will point to the reply list in the
 * message.
 * @para reply_count output. on success will contain the length of the reply
 * list.
 * @return 0 on success. -1 if the reply list is absent.
 */
static int
msg_info_reply_get(msg* msg, as_hb_mesh_info_reply** reply, size_t* reply_count)
{

	if (msg_get_buf(msg, AS_HB_MSG_HB_DATA, (uint8_t**)reply, reply_count,
			MSG_GET_DIRECT) != 0) {
		return -1;
	}

	// correct reply list length.
	*reply_count /= sizeof(as_hb_mesh_info_reply);
	return 0;
}

/**
 * Fill source fields for the message.
 * @param msg the message to fill the source fields into.
 */
static void
msg_src_fields_fill(msg* msg)
{
	// Set the hb protocol id / version.
	if (msg_set_uint32(msg, AS_HB_MSG_ID, AS_HB_PROTOCOL_IDENTIFIER()) !=
	    0) {
		CRASH("Error setting heartbeat protocol on msg.");
	}

	// Set the source node.
	if (msg_set_uint64(msg, AS_HB_MSG_NODE, config_self_nodeid_get()) !=
	    0) {
		CRASH("Error setting node id on msg.");
	}

	as_hb_ipaddr* self_addr = config_hb_publish_addr_get();
	if (!HB_IS_MSG_LEGACY(msg)) {
		// Set the source address
		if (msg_set_buf(msg, AS_HB_MSG_ADDR, (uint8_t*)self_addr,
				sizeof(*self_addr), MSG_SET_COPY) != 0) {
			CRASH("Error setting heartbeat address on msg.");
		}
	} else {

		// Set the source address. V2 only supports ipv4, casting
		// address to 32 bits. This will break if the ip address is
		// ipv6.
		if (msg_set_uint32(msg, AS_HB_MSG_ADDR,
				   as_hb_ipaddr_to_ipv4h(self_addr)) != 0) {
			CRASH("Error setting heartbeat address on msg.");
		}
	}

	if (msg_set_uint32(msg, AS_HB_MSG_PORT, config_hb_publish_port_get()) !=
	    0) {
		CRASH("Error setting heartbeat port on msg.");
	}

	// Include the ANV length in all heartbeat protocol v2 and
	// greater messages.
	if (config_protocol_get() != AS_HB_PROTOCOL_V1) {
		if (0 >
		    msg_set_uint32(msg, AS_HB_MSG_MAX_CLUSTER_SIZE,
				   (uint32_t)g_config.paxos_max_cluster_size))
			CRASH("Failed to set ANV "
			      "length in heartbeat "
			      "protocol v2 message.");
	}

	// Set the send timestamp
	if (!HB_IS_MSG_LEGACY(msg) &&
	    msg_set_uint64(msg, AS_HB_MSG_HLC_TIMESTAMP,
			   as_hlc_timestamp_now()) != 0) {
		CRASH("Error setting send timestamp on msg.");
	}
}

/**
 * Set the type for an outgoing message.
 * @param msg the outgoind message.
 * @param msg_type the type to set.
 */
static void
msg_type_set(msg* msg, as_hb_msg_type msg_type)
{
	// Set the message type.
	if (msg_set_uint32(msg, AS_HB_MSG_TYPE, msg_type) != 0) {
		CRASH("Error setting type on msg.");
	}
}

/**
 * Number of nodes supported for a give message size.
 */
static int
msg_supported_nodes_get(int msg_buffer_size)
{
	if (HB_IS_PROTOCOL_LEGACY()) {
		// Fixed payload length
		size_t fixed_payload_size = msg_get_template_fixed_sz(
		  g_hb_v2_msg_template,
		  sizeof(g_hb_v2_msg_template) / sizeof(msg_template));

		// Also accomodate for the terminating '0' nodeid.
		int supported_cluster_size =
		  ((msg_buffer_size - UDP_HEADER_SIZE_MAX -
		    fixed_payload_size) /
		   8) -
		  1;

		return supported_cluster_size;
	}

	// Calculate the fixed size for a UDP packet and the message header.
	size_t msg_fixed_size = msg_get_template_fixed_sz(
	  g_hb_msg_template, sizeof(g_hb_msg_template) / sizeof(msg_template));

	size_t msg_plugin_per_node_size = 0;

	for (int i = 0; i < AS_HB_PLUGIN_SENTINEL; i++) {
		// Adding plugin specific fixed size
		msg_fixed_size += g_hb.plugins[i].wire_size_fixed;
		// Adding plugin specific per node size.
		msg_plugin_per_node_size += g_hb.plugins[i].wire_size_per_node;
	}

	// TODO: compute the max cluster size using max storage per node in
	// cluster and the min mtu.
	int supported_cluster_size = MAX(
	  1,
	  (((msg_buffer_size - UDP_HEADER_SIZE_MAX) * MSG_COMPRESSION_RATIO) -
	   msg_fixed_size) /
	    msg_plugin_per_node_size);

	return supported_cluster_size;
}

/*----------------------------------------------------------------------------
 * Config submodule.
 *----------------------------------------------------------------------------*/

/**
 * Initialize heartbeat configuration.
 */
static void
config_init()
{
	CONFIG_LOCK();

	// Initialize the heartbeat listen and publish addresses
	char* hb_addr_to_listen = g_config.hb_config.hb_listen_addr_s;

	// Checking the first byte is enough as '0' cannot be a valid IP address
	// other than 0.0.0.0
	if (*hb_addr_to_listen == 0 || *hb_addr_to_listen == '0' ||
	    strcmp("any", hb_addr_to_listen) == 0) {
		if (g_config.hb_config.hb_mode == AS_HB_MODE_MCAST) {
			CRASH("Multicast group address not specified.");
		}
		// Bind to all interface if none specified.
		hb_addr_to_listen = "0.0.0.0";
	}

	INFO("Using %s as the IP address for receiving heartbeats",
	     hb_addr_to_listen);

	struct in_addr in_addr_to_listen;
	if (1 != inet_pton(AF_INET, hb_addr_to_listen, &in_addr_to_listen)) {
		CRASH("Invalid heartbeat ip address %s: Error:%s",
		      hb_addr_to_listen, cf_strerror(errno));
	}

	as_hb_ipaddr_from_ipv4(*(uint32_t*)&in_addr_to_listen,
			       &g_config.hb_config.hb_listen_addr);

	strncpy(g_config.hb_config.hb_listen_addr_s, hb_addr_to_listen,
		sizeof(g_config.hb_config.hb_listen_addr_s));

	struct in_addr in_addr_bind;
	if (*g_config.hb_config.hb_bind_interface_addr_s) {
		if (1 != inet_pton(AF_INET,
				   g_config.hb_config.hb_bind_interface_addr_s,
				   &in_addr_bind)) {
			CRASH("Invalid heartbeat bind address %s. Error:%s",
			      g_config.hb_config.hb_bind_interface_addr_s,
			      cf_strerror(errno));
		}

		as_hb_ipaddr_from_ipv4(
		  *(uint32_t*)&in_addr_bind,
		  &g_config.hb_config.hb_bind_interface_addr);

		INFO("Listening to interface with address %s",
		     g_config.hb_config.hb_bind_interface_addr_s);
	} else {
		memset(&g_config.hb_config.hb_bind_interface_addr, 0,
		       sizeof(g_config.hb_config.hb_bind_interface_addr));
		g_config.hb_config.hb_bind_interface_addr_s[0] = 0;
	}

	if (as_hb_ipaddr_is_specified(
	      &g_config.hb_config.hb_bind_interface_addr)) {
		// An interface address is specified. Use that ip as the publish
		// ip.
		inet_ntop(AF_INET, &in_addr_bind,
			  g_config.hb_config.hb_publish_addr_s,
			  sizeof(g_config.hb_config.hb_publish_addr_s));
	} else {
		// Use node ip as the publish ip.
		strncpy(g_config.hb_config.hb_publish_addr_s, g_config.node_ip,
			sizeof(g_config.hb_config.hb_publish_addr_s));
	}

	struct in_addr in_addr_to_publish;
	if (1 != inet_pton(AF_INET, g_config.hb_config.hb_publish_addr_s,
			   &in_addr_to_publish)) {
		CRASH("Invalid heartbeat ip address %s: Error:%s",
		      g_config.hb_config.hb_publish_addr_s, cf_strerror(errno));
	}

	as_hb_ipaddr_from_ipv4(*(uint32_t*)&in_addr_to_publish,
			       &g_config.hb_config.hb_publish_addr);
	g_config.hb_config.hb_publish_port = g_config.hb_config.hb_listen_port;

	INFO("Using %s:%d as the published IP address",
	     g_config.hb_config.hb_publish_addr_s,
	     g_config.hb_config.hb_publish_port);

	CONFIG_UNLOCK();
}

/**
 * Get mssize.
 */
static int
config_mcsize()
{

	int mode_cluster_size = 0;
	if (IS_MESH()) {
		// Only bounded by available memory. But let's say its
		// inifinite.
		mode_cluster_size = INT_MAX;
	} else {
		mode_cluster_size = multicast_supported_cluster_size_get();
	}

	// Ensure we are always upper bounded by the absolute max cluster size.
	int supported_cluster_size =
	  MIN(ASC, MIN(g_config.paxos_max_cluster_size, mode_cluster_size));

	DETAIL("Supported cluster size %d", supported_cluster_size);
	return supported_cluster_size;
}

/**
 * Get the ip address that this node publishes.
 */
static as_hb_ipaddr*
config_hb_publish_addr_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return &g_config.hb_config.hb_publish_addr;
}

/**
 * Get the port this node publishes as its heartbeat port.
 */
static int
config_hb_publish_port_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_publish_port;
}

/**
 * Get the ip address that this node listens.
 */
static as_hb_ipaddr*
config_hb_listen_addr_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return &g_config.hb_config.hb_listen_addr;
}

/**
 * Get the ip address that this node listens.
 */
static char*
config_hb_listen_addr_s_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_listen_addr_s;
}

/**
 * Get the ip address published by this node.
 */
static char*
config_hb_publish_addr_s_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_publish_addr_s;
}

/**
 * Get the ip address that this node is bind to.
 */
static char*
config_hb_bind_interface_addr_s_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_bind_interface_addr_s;
}

/**
 * Get the port this node listens as its heartbeat port.
 */
static int
config_hb_listen_port_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_listen_port;
}

/**
 * Get the ip address that interface to bind to for listening.
 */
static as_hb_ipaddr*
config_hb_bind_interface_addr_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return &g_config.hb_config.hb_bind_interface_addr;
}

/**
 * Get the heartbeat pulse transmit interval.
 */
static uint32_t
config_hb_tx_interval_get()
{
	CONFIG_LOCK();
	uint32_t interval = g_config.hb_config.hb_tx_interval;
	CONFIG_UNLOCK();
	return interval;
}

/**
 * Set the heartbeat pulse transmit interval.
 */
static void
config_hb_tx_interval_set(uint32_t new_interval)
{
	CONFIG_LOCK();
	INFO("Changing value of interval from %d to %d ",
	     g_config.hb_config.hb_tx_interval, new_interval);
	g_config.hb_config.hb_tx_interval = new_interval;
	CONFIG_UNLOCK();
}

/**
 * Get the heartbeat pulse transmit interval.
 */
static uint32_t
config_override_mtu_get()
{
	CONFIG_LOCK();
	uint32_t override_mtu = g_config.hb_config.override_mtu;
	CONFIG_UNLOCK();
	return override_mtu;
}

/**
 * Set the heartbeat pulse transmit interval.
 */
static void
config_override_mtu_set(uint32_t mtu)
{
	CONFIG_LOCK();
	INFO("Changing value of override mtu from %d to %d ",
	     g_config.hb_config.override_mtu, mtu);
	g_config.hb_config.override_mtu = mtu;
	CONFIG_UNLOCK();
	INFO("Max supported cluster size is %d.",
	     multicast_supported_cluster_size_get());
}

/**
 * Get the maximum number of missed heartbeat intervals after which a node is
 * considered expired.
 */
static uint32_t
config_hb_max_intervals_missed_get()
{
	uint32_t rv = 0;
	CONFIG_LOCK();
	rv = g_config.hb_config.hb_max_intervals_missed;
	CONFIG_UNLOCK();
	return rv;
}

/**
 * Set the maximum number of missed heartbeat intervals after which a node is
 * considered expired.
 */
static void
config_hb_max_intervals_missed_set(uint32_t new_max)
{
	CONFIG_LOCK();
	INFO("Changing value of timeout from %d to %d ",
	     g_config.hb_config.hb_max_intervals_missed, new_max);
	g_config.hb_config.hb_max_intervals_missed = new_max;
	CONFIG_UNLOCK();
}

/**
 * Get multiple of 'hb max intervals missed' during which if no fabric messages
 * arrive from a node, the node is considered fabric expired. A value of < 0
 * indicates infinite fabric grace timeout.
 */
static int
config_hb_fabric_grace_factor_get()
{
	CONFIG_LOCK();
	int rv = g_config.hb_config.hb_fabric_grace_factor;
	CONFIG_UNLOCK();
	return rv;
}

/**
 * Set multiple of 'hb max intervals missed' during which if no fabric messages
 * arrive from a node, the node is considered fabric expired. Set to -1 for
 * infinite grace period.
 */
static void
config_hb_fabric_grace_factor_set(int new_factor)
{
	CONFIG_LOCK();
	INFO("Changing value of fabric grace factor from %d to %d ",
	     g_config.hb_config.hb_fabric_grace_factor, new_factor);
	g_config.hb_config.hb_fabric_grace_factor = new_factor;
	CONFIG_UNLOCK();
}

/**
 * Get the heartbeat pulse transmit interval.
 */
static uint32_t
config_hb_mesh_rw_retry_timeout_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_mesh_rw_retry_timeout;
}

/**
 * Return ttl for multicast packets. Set to zero for default TTL.
 */
static unsigned char
config_hb_mcast_ttl_get()
{
	return g_config.hb_config.hb_mcast_ttl;
}

/**
 * Return the current heartbeat protocol.
 */
static hb_protocol_enum
config_protocol_get()
{
	hb_protocol_enum rv = 0;
	CONFIG_LOCK();
	rv = g_config.hb_config.hb_protocol;
	CONFIG_UNLOCK();
	return rv;
}

/**
 * Return the current heartbeat protocol.
 */
static void
config_protocol_set(hb_protocol_enum new_protocol)
{
	CONFIG_LOCK();
	g_config.hb_config.hb_protocol = new_protocol;
	CONFIG_UNLOCK();
}

/**
 * The nodeid for this node.
 */
static cf_node
config_self_nodeid_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.self_node;
}

/**
 * Return the heartbeat subsystem mode.
 */
static hb_mode_enum
config_mode_get()
{
	// Not protected by config_lock beacuse it is not changed.
	return g_config.hb_config.hb_mode;
}

/*----------------------------------------------------------------------------
 * Channel submodule.
 *----------------------------------------------------------------------------*/

/**
 * Enable / disable events.
 */
static void
channel_events_enabled_set(bool enabled)
{
	CHANNEL_LOCK();
	g_hb.channel_state.events_enabled = enabled;
	CHANNEL_UNLOCK();
}

/**
 * Know if events are enabled.
 */
static bool
channel_are_events_enabled()
{
	bool result;
	CHANNEL_LOCK();
	result = g_hb.channel_state.events_enabled;
	CHANNEL_UNLOCK();
	return result;
}

/**
 * Queues a channel event for publishing by the channel tender.
 */
static void
channel_event_queue(as_hb_channel_event* event)
{

	if (!channel_are_events_enabled()) {
		DETAIL("Events disabled. Ignoring event of type %d with nodeid "
		       "%" PRIx64,
		       event->type, event->nodeid);
		return;
	}

	DETAIL("Queuing channel event of type %d for node %" PRIx64,
	       event->type, event->nodeid);
	if (cf_queue_push(&g_hb.channel_state.events_queue, event) != 0) {
		CRASH("Error queuing up external heartbeat event for "
		      "node %" PRIx64,
		      event->nodeid);
	}
}

/**
 * Publish queued up channel events. Should be called outside a channel lock to
 * prevent deadlocks.
 */
static void
channel_event_publish_pending()
{
	// No channel lock here to prevent deadlocks.
	as_hb_channel_event event;
	while (cf_queue_pop(&g_hb.channel_state.events_queue, &event, 0) ==
	       CF_QUEUE_OK) {

		// Nothing elaborate, using hardcoded list of event recepients.
		mesh_channel_event_process(&event);
		hb_channel_event_process(&event);

		// Free the message structure for message received events.
		if (event.type == AS_HB_CHANNEL_MSG_RECEIVED) {
			hb_msg_return(event.msg);
		}
	}
}

/**
 * Return the endpoint associated with this socket if it exists.

 * @param socket the socket to query for.
 * @param result the output result.
 * @return 0 if the socket was found and the result value is filled. -1 if a mapping
 for the socket coud not be found.
*/
static int
channel_get_channel(cf_socket* socket, as_hb_channel* result)
{
	int status;
	CHANNEL_LOCK();

	if (SHASH_OK ==
	    shash_get(g_hb.channel_state.socket_to_channel, &socket, result)) {
		status = 0;
	} else {
		status = -1;
	}

	CHANNEL_UNLOCK();
	return status;
}

/**
 * Shutdown a channel socket without closing, forcing the channel tender to cleanup
 * associated data structures.
 */
static void
channel_socket_shutdown(cf_socket* socket)
{
	cf_socket_shutdown(socket);
}

/**
 * Return the socket associated with this node.
 * Returns 0 on success and -1 if there is no socket attached to this node.
 */
static int
channel_socket_get(cf_node nodeid, cf_socket** socket)
{
	int rv = -1;
	CHANNEL_LOCK();
	if (SHASH_GET_OR_DIE(g_hb.channel_state.nodeid_to_socket, &nodeid, socket,
			     "Error get channel information for node %" PRIX64,
			     nodeid) == SHASH_ERR_NOTFOUND) {
		rv = -1;
	} else {
		rv = 0;
	}

	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Close a channel socket. Precondition is that the socket is registerd
 * with the channel module using channel_socket_register.
 */
static void
channel_socket_close(cf_socket* socket, bool remote_close, bool raise_close_event)
{
	if (remote_close) {
		stats_error_count(AS_HB_ERR_REMOTE_CLOSE);
		DEBUG("Remote close: fd %d event.", CSFD(socket));
	}

	CHANNEL_LOCK();

	// clean up data structures.
	as_hb_channel channel;
	int status = channel_get_channel(socket, &channel);

	if (status == 0) {

		if (channel.nodeid != 0) {

			SHASH_DELETE_OR_DIE(
			  g_hb.channel_state.nodeid_to_socket, &channel.nodeid,
			  "Error deleting fd associated with %" PRIx64,
			  channel.nodeid);

			if (!channel.is_multicast && raise_close_event) {
				as_hb_channel_event event;
				// Notify others that this node is no longer
				// connected.
				event.type = AS_HB_CHANNEL_NODE_DISCONNECTED;
				event.nodeid = channel.nodeid;
				event.msg = NULL;

				channel_event_queue(&event);
			}
		}

		DETAIL(
		  "Removed channel associated with fd %d Polarity %s Type: %s",
		  CSFD(socket), channel.is_inbound ? "inbound" : "outbound",
		  channel.is_multicast ? "multicast" : "mesh");
		// Remove associated channel.
		SHASH_DELETE_OR_DIE(g_hb.channel_state.socket_to_channel, &socket,
				    "Error deleting channel for fd %d",
				    CSFD(socket));

	} else {
		// Will only happen if we are closing this socket twice. Cannot
		// deference the underlying fd because the socket has been
		// freed.
		WARNING("Found a socket %p without an "
			"associated channel.",
				socket);
		goto Exit;
	}

	static int32_t err_ok[] = { ENOENT, EBADF, EPERM };
	int32_t err = cf_poll_delete_socket_forgiving(
	  g_hb.channel_state.poll, socket, sizeof(err_ok) / sizeof(int32_t),
	  err_ok);

	if (err == ENOENT) {
		// There is no valid code path where epoll ctl should fail
		CRASH("Unable to remove fd %d from epoll fd list: %s",
		      CSFD(socket), cf_strerror(errno));
		// might close a newly acquired socket.
		goto Exit;
	}

	cf_atomic_int_incr(&g_stats.heartbeat_connections_closed);
	DEBUG("Closing channel with fd %d", CSFD(socket));

	if (socket != g_hb.channel_state.listening_socket) {
		// Listening sockets will be closed by the mode (mesh/multicast
		// ) modules.
		cf_socket_close(socket);
	}

Exit:
	CHANNEL_UNLOCK();
}

/**
 * Close multiple sockets. Should be invoked only by channel stop.
 * @param sockets the vector consisting of sockets to be closed.
 */
static void
channel_sockets_close(cf_vector* sockets)
{
	uint32_t socket_count = cf_vector_size(sockets);
	for (int index = 0; index < socket_count; index++) {
		cf_socket* socket;
		if (cf_vector_get(sockets, index, &socket) != 0) {
			WARNING("Error finding the fd %d to be deleted.",
				CSFD(socket));
			continue;
		}
		channel_socket_close(socket, false, true);
	}
}

/**
 * Queues a socket for closing by the channel tender. Should be used by all code
 * paths other than the channel stop code path.
 */
static void
channel_socket_close_queue(cf_socket* socket, bool is_remote_close,
		       bool raise_close_event)
{

	as_hb_channel_socket_close_entry close_entry = { socket, is_remote_close,
						     raise_close_event };
	DETAIL("Queuing close of fd %d", CSFD(socket));
	if (cf_queue_push(&g_hb.channel_state.socket_close_queue, &close_entry) !=
	    0) {
		CRASH("Error queuing up close of fd %d", CSFD(socket));
	}
}

/**
 * Closed queued up sockets.
 */
static void
channel_socket_close_pending()
{
	// No channel lock required here.
	as_hb_channel_socket_close_entry close_entry;
	while (cf_queue_pop(&g_hb.channel_state.socket_close_queue, &close_entry,
			    0) == CF_QUEUE_OK) {

		channel_socket_close(close_entry.socket, close_entry.is_remote,
				 close_entry.raise_close_event);
	}
}

/**
 * Register a new socket.
 *
 * @param socket the socket.
 * @param is_multicast indicates if this socket is a multicast socket.
 * @param is_inbound indicates if this socket is an inbound / outbound.
 * @param endpoint connected endpoint to. Can be NULL.
 */
static void
channel_socket_register(cf_socket* socket, bool is_multicast, bool is_inbound,
		    as_hb_endpoint* endpoint)
{
	CHANNEL_LOCK();

	as_hb_channel channel;

	// This socket should not be part of the socket to channel map.
	ASSERT(channel_get_channel(socket, &channel) == -1,
	       "Error the channel already exists for fd %d", CSFD(socket));

	memset(&channel, 0, sizeof(channel));
	channel.is_multicast = is_multicast;
	channel.is_inbound = is_inbound;
	channel.last_received = cf_getms();

	if (endpoint) {
		memcpy(&channel.endpoint, endpoint, sizeof(as_hb_endpoint));
	}

	// Add socket to poll list
	cf_poll_add_socket(g_hb.channel_state.poll, socket,
			   EPOLLIN | EPOLLERR | EPOLLRDHUP, socket);

	SHASH_PUT_OR_DIE(g_hb.channel_state.socket_to_channel, &socket, &channel,
			 "Error allocating memory for channel fd %d", CSFD(socket));

	DEBUG("Channel created for fd %d. Polarity %s Type: %s", CSFD(socket),
	      channel.is_inbound ? "inbound" : "outbound",
	      channel.is_multicast ? "multicast" : "mesh");

	CHANNEL_UNLOCK();
}

/**
 * Accept an incomming tcp connection. For now this is relevant only to
 * the mesh mode.
 */
static void
channel_accept_connection()
{
	if (!IS_MESH()) {
		// We do not accept connections in non mesh modes.
		return;
	}

	// Apparently accept failures, once they happen, are very
	// frequent. Print only once per second.
	static cf_clock last_accept_fail_print = 0;

	cf_socket* csock;
	cf_sock_addr caddr;

	if (cf_socket_accept(g_hb.channel_state.listening_socket, &csock,
			     &caddr) < 0) {
		if ((errno == EMFILE) || (errno == ENFILE) ||
		    (errno == ENOMEM) || (errno == ENOBUFS)) {
			if (last_accept_fail_print != (cf_getms() / 1000L)) {
				WARNING("Failed to accept "
					"heartbeat "
					"connection due to "
					"error : %s",
					cf_strerror(errno));
				last_accept_fail_print = cf_getms() / 1000L;
			}
			// We are in an extreme situation where we ran out of
			// system resources (file/mem). We should rather lie low
			// and not do too much activity. So, sleep. We should
			// not sleep too long as this same function is supposed
			// to send heartbeat also.
			usleep(MAX(config_hb_tx_interval_get() / 2, 1) * 1000);
			return;
		} else {
			// TODO: Find what there errors are.
			WARNING("Accept failed: %s", cf_strerror(errno));
			return;
		}
	}

	// Update the stats to reflect to a new connection opened.
	cf_atomic_int_incr(&g_stats.heartbeat_connections_opened);

	char caddr_str[HOST_NAME_MAX];
	cf_sock_addr_to_string_safe(&caddr, caddr_str, sizeof(caddr_str));
	DEBUG("New connection from %s", caddr_str);

	// Make the socket nonblocking.
	cf_socket_disable_blocking(csock);
	cf_socket_disable_nagle(csock);

	// Register this socket with the channel subsystem.
	channel_socket_register(csock, false, true, NULL);
}

/**
 * Parse compressed buffer into a message.
 *
 * @param msg the input parsed compressed message and also the output heartbeat
 * message.
 * @param buffer the input buffer.
 * @param buffer_content_len the length of the content in the buffer.
 * @return the status of parsing the message.
 */
static as_hb_channel_msg_read_status
channel_compressed_message_parse(msg* msg, void* buffer, int buffer_content_len)
{
	// This is a direct pointer inside the buffer parameter. No
	// allocation required.
	uint8_t* compressed_buffer = NULL;
	size_t compressed_buffer_length = 0;
	int parsed = AS_HB_CHANNEL_MSG_PARSE_FAIL;
	void* uncompressed_buffer = NULL;
	size_t uncompressed_buffer_length = 0;

	if (msg_get_buf(msg, AS_HB_MSG_COMPRESSED_PAYLOAD, &compressed_buffer,
			&compressed_buffer_length, MSG_GET_DIRECT) != 0) {
		parsed = AS_HB_CHANNEL_MSG_PARSE_FAIL;
		goto Exit;
	}

	// Assume compression ratio of 3. We will expand the buffer if
	// needed.
	uncompressed_buffer_length =
	  round_up_pow2(3 * compressed_buffer_length);

	// Keep trying till we allocate enough memory for the
	// uncompressed buffer.
	while (true) {
		uncompressed_buffer = MSG_BUFF_ALLOC_OR_DIE(
		  uncompressed_buffer_length, "Error allocating memory size "
					      "%zu for uncompressing message",
		  uncompressed_buffer_length);

		int uncompress_rv =
		  uncompress(uncompressed_buffer, &uncompressed_buffer_length,
			     compressed_buffer, compressed_buffer_length);

		if (uncompress_rv == Z_OK) {
			// Uncompression was successful.
			break;
		}

		if (uncompress_rv == Z_BUF_ERROR) {
			// The uncompressed buffer is not large enough. Free
			// current buffer and allocate a new buffer.
			MSG_BUFF_FREE(uncompressed_buffer,
				      uncompressed_buffer_length);

			// Give uncompressed buffer more space.
			uncompressed_buffer_length *= 2;
			continue;
		}

		// Un compression failed. Clean up and exit.
		parsed = AS_HB_CHANNEL_MSG_PARSE_FAIL;
		goto Exit;
	}

	// Reset the message to prepare for parsing the uncompressed buffer. We
	// have no issues losing the compressed buffer because we have an
	// uncompressed copy.
	msg_reset(msg);

	// Parse the uncompressed buffer.
	parsed =
	  msg_parse(msg, uncompressed_buffer, uncompressed_buffer_length) == 0
	    ? AS_HB_CHANNEL_MSG_READ_SUCCESS
	    : AS_HB_CHANNEL_MSG_PARSE_FAIL;

	if (parsed == AS_HB_CHANNEL_MSG_READ_SUCCESS) {
		// Copying the buffer content to ensure that the message
		// and the buffer can have separate lifecycles and we never get
		// into races. The frequency of heartbeat messages is low enough
		// to make this not matter much unless we have massive clusters.
		msg_preserve_all_fields(msg);
	}

Exit:
	MSG_BUFF_FREE(uncompressed_buffer, uncompressed_buffer_length);
	return parsed;
}

/**
 * Parse the buffer into a message.
 *
 * @param msg the output heartbeat message.
 * @param buffer the input buffer.
 * @param buffer_content_len the length of the content in the buffer.
 * @return the status of parsing the message.
 */
static as_hb_channel_msg_read_status
channel_message_parse(msg* msg, void* buffer, int buffer_content_len)
{

	// Peek into the buffer to get hold of the message type.
	bool parsed = msg_parse(msg, buffer, buffer_content_len) == 0;

	if (parsed) {

		if (!HB_IS_MSG_LEGACY(msg) &&
		    msg_is_set(msg, AS_HB_MSG_COMPRESSED_PAYLOAD)) {
			// This is a compressed message.
			return channel_compressed_message_parse(
			  msg, buffer, buffer_content_len);
		}

		// This is an uncompressed message. Copying the buffer content
		// to ensure that the message and the buffer can have separate
		// lifecycles and we never get into races. The frequency of
		// heartbeat messages is low enough to make this not matter much
		// unless we have massive clusters.
		msg_preserve_all_fields(msg);
	}

	return parsed ? AS_HB_CHANNEL_MSG_READ_SUCCESS
		      : AS_HB_CHANNEL_MSG_PARSE_FAIL;
}

/**
 * Reduce function to find a matching endpoint.
 */
static int
channel_endpoint_search_reduce(void* key, void* data, void* udata)
{

	cf_socket** socket = (cf_socket**)key;
	as_hb_channel* channel = (as_hb_channel*)data;
	as_hb_channel_endpoint_reduce_udata* endpoint_reduce_udata =
	  (as_hb_channel_endpoint_reduce_udata*)udata;

	if (memcmp(&channel->endpoint, endpoint_reduce_udata->endpoint,
		   sizeof(as_hb_endpoint)) == 0) {
		endpoint_reduce_udata->found = true;
		endpoint_reduce_udata->socket = *socket;
	}

	return SHASH_OK;
}

/**
 * Get all sockets.
 */
static int
channel_sockets_get_reduce(void* key, void* data, void* udata)
{
	cf_vector* sockets = (cf_vector*)udata;
	cf_vector_append(sockets, key);
	return SHASH_OK;
}

/**
 * Indicates if an endpoint is connected.
 * @param endpoint the endpoint to check.
 * @return true if the endpoint is already connected to, false otherwise.
 */
static bool
channel_endpoint_is_connected(as_hb_endpoint* endpoint)
{
	CHANNEL_LOCK();
	// Linear search. This will in practice not be a very frequent
	// operation.
	as_hb_channel_endpoint_reduce_udata udata;
	memset(&udata, 0, sizeof(udata));
	udata.endpoint = endpoint;

	shash_reduce(g_hb.channel_state.socket_to_channel,
		     channel_endpoint_search_reduce, &udata);

	CHANNEL_UNLOCK();
	return udata.found;
}

/**
 * Read a message from the multicast socket.
 *
 * @param socket the multicast socket to read from.
 * @param msg the message to read into.
 *
 * @return the status the read operation.
 */
static as_hb_channel_msg_read_status
channel_multicast_msg_read(cf_socket* socket, msg* msg)
{
	CHANNEL_LOCK();

	as_hb_channel_msg_read_status rv = AS_HB_CHANNEL_MSG_READ_UNDEF;

	int buffer_len = MTU();
	uint8_t* buffer = MSG_BUFF_ALLOC(buffer_len);

	if (!buffer) {
		WARNING("Error allocating space for multicast recv buffer of "
			"size %d on fd %d",
			buffer_len, CSFD(socket));
		goto Exit;
	}

	cf_sock_addr from;

	int num_rcvd = cf_socket_recv_from(socket, buffer, buffer_len, 0, &from);

	if (num_rcvd <= 0) {
		DEBUG("Multicast packed read failed on fd %d", CSFD(socket));
		rv = AS_HB_CHANNEL_MSG_CHANNEL_FAIL;
		goto Exit;
	}

	rv = channel_message_parse(msg, buffer, num_rcvd);
	if (rv != AS_HB_CHANNEL_MSG_READ_SUCCESS) {
		goto Exit;
	}

	if (HB_IS_MSG_LEGACY(msg)) {
		uint32_t addr = as_cf_ipaddr_to_ipv4h(&from.addr);
		// Set AS_HB_MSG_ADDR,  as heartbeat version v2 does not set
		// this in the message header for multicast, but we expect
		// the source address to be present in the header.
		if (msg_set_uint32(msg, AS_HB_MSG_ADDR, addr) != 0) {
			CRASH("Error setting heartbeat address on msg.");
		}
		if (msg_set_uint32(msg, AS_HB_MSG_PORT,
				   config_hb_publish_port_get()) != 0) {
			CRASH("Error setting heartbeat port on msg.");
		}
	}
	rv = AS_HB_CHANNEL_MSG_READ_SUCCESS;

Exit:

	MSG_BUFF_FREE(buffer, buffer_len);

	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Read a message from the a tcp mesh socket.
 *
 * @param socket the tcp socket to read from.
 * @param msg the message to read into.
 *
 * @return status of the read operation.
 */
static as_hb_channel_msg_read_status
channel_mesh_msg_read(cf_socket* socket, msg* msg)
{
	CHANNEL_LOCK();

	uint32_t buffer_len = 0;
	uint8_t* buffer = NULL;

	as_hb_channel_msg_read_status rv = AS_HB_CHANNEL_MSG_READ_UNDEF;
	int flags = (MSG_NOSIGNAL | MSG_PEEK);
	uint8_t len_buff[MSG_WIRE_LENGTH_SIZE];

	if (MSG_WIRE_LENGTH_SIZE >
	    cf_socket_recv(socket, len_buff, MSG_WIRE_LENGTH_SIZE, flags)) {
		WARNING("On fd %d recv peek error", CSFD(socket));
		rv = AS_HB_CHANNEL_MSG_CHANNEL_FAIL;
		goto Exit;
	}

	buffer_len = ntohl(*((uint32_t*)len_buff)) + 6;

	buffer = MSG_BUFF_ALLOC(buffer_len);

	memcpy(buffer, len_buff, MSG_WIRE_LENGTH_SIZE);

	if (!buffer) {
		WARNING("Error allocating space for multicast recv buffer of "
			"size %d on fd %d",
			buffer_len, CSFD(socket));
		goto Exit;
	}

	int try_num = MSG_READ_RETRY_MAX;
	// Note: Buffer length includes the length as well.
	int read_so_far = 0;
	cf_clock start = cf_getus();

	do {

		DETAIL("reading from tcp fd %d try %d remaining %d", CSFD(socket),
		       try_num, buffer_len - read_so_far);

		int ret =
		  cf_socket_recv(socket, (buffer + read_so_far),
				 buffer_len - read_so_far, MSG_NOSIGNAL);

		if (ret < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
			// Channel failure.
			DEBUG("Channel failure reading message on fd %d",
			      CSFD(socket));
			break;
		}

		read_so_far += ret > 0 ? ret : 0;

		if (read_so_far == buffer_len) {
			// Successful recv.
			break;
		}

		// Wait for a while and retry.
		usleep(MESH_RW_TIMEOUT() / MSG_READ_RETRY_MAX);

	} while (--try_num > 0 && ((start + MESH_RW_TIMEOUT()) > cf_getus()));

	if (read_so_far < buffer_len) {
		// Recv incomplete.
		DETAIL("mesh recv failed fd %d try %d message size %d",
		       CSFD(socket), try_num, buffer_len);
		rv = AS_HB_CHANNEL_MSG_CHANNEL_FAIL;
		goto Exit;
	}

	DETAIL("mesh recv success fd %d try %d message size %d", CSFD(socket),
	       try_num, buffer_len);

	rv = channel_message_parse(msg, buffer, buffer_len);
Exit:

	MSG_BUFF_FREE(buffer, buffer_len);

	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Associate a socket with a nodeid and notify listeners about a node being
 * connected, effective only for mesh channels.
 *
 * For multicast channels this function is a no-op. The reason being additional
 * machinery would be required to clean up the node to channel mapping on node
 * expiry.
 *
 * @param socket the socket.
 * @param channel the channel to associate.
 * @param nodeid the nodeid assocaited with this socket.
 * @param endpoint the node's endpoint.
 */
static void
channel_node_attach(cf_socket* socket, as_hb_channel* channel, cf_node nodeid,
		    as_hb_endpoint* endpoint)
{

	// For now node to socket mapping is not maintained for
	// multicast channels.
	if (channel->is_multicast) {
		return;
	}

	CHANNEL_LOCK();

	// Update the node information for the channel.

	// This is the first time this node has a connection. Record the
	// mapping.

	SHASH_PUT_OR_DIE(g_hb.channel_state.nodeid_to_socket, &nodeid, &socket,
			 "Error associating node %" PRIX64 " with fd %d",
			 nodeid, CSFD(socket));

	channel->nodeid = nodeid;
	if (endpoint) {
		memcpy(&channel->endpoint, endpoint, sizeof(as_hb_endpoint));
	}

	SHASH_PUT_OR_DIE(g_hb.channel_state.socket_to_channel, &socket, channel,
			 "Error saving nodeid %" PRIx64
			 " to channel hash for fd %d",
			 nodeid, CSFD(socket));

	DEBUG("Attached fd %d to node %" PRIx64, CSFD(socket), nodeid);

	CHANNEL_UNLOCK();

	// Publish an event to let know that a new node has a channel
	// now.
	as_hb_channel_event node_connected_event;
	memset(&node_connected_event, 0, sizeof(node_connected_event));
	node_connected_event.nodeid = nodeid;
	node_connected_event.type = AS_HB_CHANNEL_NODE_CONNECTED;
	channel_event_queue(&node_connected_event);
}

/**
 * Inidicates if a channel should be allowed to continue to win and live because
 * of a winning grace period.
 */
static bool
channel_socket_should_live(cf_socket* socket, as_hb_channel* channel)
{
	if (channel->resolution_win_ts > 0 &&
	    channel->resolution_win_ts + CHANNEL_WIN_GRACE_MS() > cf_getms()) {
		// Losing socket was a previous winner. Allow it time to do some
		// work before knocking it off.
		INFO("Giving %d unresolved fd some grace time.", CSFD(socket));
		return true;
	}
	return false;
}

/**
 * Selects one out give two sockets connected to same remote node. The
 * algorithm is
 * deterministic and ensures the remote node also chooses a socket that
 * drops the
 * same connection.
 *
 * @param socket1 one of the sockets
 * @param socket2 one of the sockets
 * @return resolved socket on success, NULL if resolution fails.
 */
static cf_socket*
channel_socket_resolve(cf_socket* socket1, cf_socket* socket2)
{
	cf_socket* rv = NULL;
	CHANNEL_LOCK();

	DEBUG("Resolving between fd %d and %d", CSFD(socket1), CSFD(socket2));

	as_hb_channel channel1;
	if (channel_get_channel(socket1, &channel1) < 0) {
		// Should not happen in practise.
		WARNING("Resolving fd %d without channel", CSFD(socket1));
		rv = socket2;
		goto Exit;
	}

	as_hb_channel channel2;
	if (channel_get_channel(socket2, &channel2) < 0) {
		// Should not happen in practise.
		WARNING("Resolving fd %d without channel", CSFD(socket2));
		rv = socket1;
		goto Exit;
	}

	if (channel_socket_should_live(socket1, &channel1)) {
		rv = socket1;
		goto Exit;
	}

	if (channel_socket_should_live(socket2, &channel2)) {
		rv = socket2;
		goto Exit;
	}

	cf_node remote_nodeid =
	  channel1.nodeid != 0 ? channel1.nodeid : channel2.nodeid;

	if (remote_nodeid == 0) {
		// Should not happen in practise.
		WARNING("Remote node id unknown for fds %d and %d", CSFD(socket1),
			CSFD(socket2));
		rv = NULL;
		goto Exit;
	}

	// Choose the socket with the highest acceptor nodeid.
	cf_node acceptor_nodeid1 =
	  channel1.is_inbound ? config_self_nodeid_get() : remote_nodeid;
	cf_node acceptor_nodeid2 =
	  channel2.is_inbound ? config_self_nodeid_get() : remote_nodeid;

	as_hb_channel* winner_channel = NULL;
	cf_socket* winner_socket = NULL;
	if (acceptor_nodeid1 > acceptor_nodeid2) {
		winner_channel = &channel1;
		winner_socket = socket1;
	} else if (acceptor_nodeid1 < acceptor_nodeid2) {
		winner_channel = &channel2;
		winner_socket = socket2;
	} else {
		// Both connections have the same acceptor. Should not happen in
		// practise. Despair and report resolution fauilure.
		INFO("Found duplicate connections to same node that cannot "
		     "be resolved with fds %d %d. Choosing at random.",
		     CSFD(socket1), CSFD(socket2));

		if (cf_getms() % 2 == 0) {
			winner_channel = &channel1;
			winner_socket = socket1;
		} else {
			winner_channel = &channel2;
			winner_socket = socket2;
		}
	}

	cf_clock now = cf_getms();
	if (winner_channel->resolution_win_ts == 0) {
		winner_channel->resolution_win_ts = now;
		// Update the winning count of the winning channel in the
		// channel data structures.
		SHASH_PUT_OR_DIE(
		  g_hb.channel_state.socket_to_channel, &winner_socket, winner_channel,
		  "Error allocating memory for channel fd %d", CSFD(winner_socket));
	}

	if (winner_channel->resolution_win_ts > now + CHANNEL_WIN_GRACE_MS()) {
		// The winner has been winning a lot, most
		// likely the
		// other side is
		// A. legacy hb code which can keep retrying and
		//    messes with this deterministic resolution.
		// Or
		// B. Has us with a seed address different from
		// our published address again break resolution.
		//
		// Break the cycle here and choose the loosing channel
		// as the winner.
		INFO("Breaking socket resolve loop dropping "
		     "winning fd %d",
		     CSFD(winner_socket));
		winner_channel =
		  (winner_channel == &channel1) ? &channel2 : &channel1;
		winner_socket = (socket1 == winner_socket) ? socket2 : socket1;
	}

	rv = winner_socket;

Exit:
	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Basic sanity check for a message.
 * @param msg the inbound message.
 * @return 0 if the message passes basic sanity tests. -1 on failure.
 */
static int
channel_msg_sanity_check(msg* msg)
{
	uint32_t id = 0;

	as_hb_msg_type type = 0;
	cf_node src_nodeid = 0;

	int rv = 0;

	if (msg_nodeid_get(msg, &src_nodeid) != 0) {
		DEBUG("Received message without a source node.");
		stats_error_count(AS_HB_ERR_NO_SRC_NODE);
		rv = -1;
	}

	// Validate the fact that we have a valid source nodeid.
	if (src_nodeid == 0) {
		// Event nodeid is zero. Not a valid source nodeid. This will
		// happen in compatibility mode if the info request from a new
		// node arrives before the pulse message. Can be ignored.
		DEBUG("Received a message from node with unknown nodeid.");
		rv = -1;
	}

	if (msg_id_get(msg, &id) != 0) {
		DEBUG("Received message without heartbeat protocol identifier "
		      "form node %" PRIx64,
		      src_nodeid);
		stats_error_count(AS_HB_ERR_NO_ID);
		rv = -1;
	} else {
		DETAIL("Received message with heartbeat protocol identifier %d "
		       "from node %" PRIx64,
		       id, src_nodeid);

		// Ignore the message if the protocol of the
		// incoming message does not match.
		if (id != AS_HB_PROTOCOL_IDENTIFIER()) {
			DEBUG("Received message with different heartbeat "
			      "protocol identifier"
			      "form node "
			      "%" PRIx64,
			      src_nodeid);
			stats_error_count(
			  AS_HB_ERR_HEARTBEAT_PROTOCOL_MISMATCH);
			rv = -1;
		}
	}

	if (msg_type_get(msg, &type) != 0) {
		DEBUG(
		  "Received message without message type form node %" PRIx64,
		  src_nodeid);
		stats_error_count(AS_HB_ERR_NO_TYPE);
		rv = -1;
	}

	as_hb_endpoint endpoint;
	if (msg_endpoint_get(msg, &endpoint) != 0) {
		DEBUG(
		  "Received message without address/port form node %" PRIx64,
		  src_nodeid);
		stats_error_count(AS_HB_ERR_NO_ENDPOINT);
		rv = -1;
	}

	as_hlc_timestamp send_ts;
	if (msg_send_ts_get(msg, &send_ts) != 0) {
		DEBUG("Received message without HLC time form node %" PRIx64,
		      src_nodeid);
		stats_error_count(AS_HB_ERR_NO_SEND_TS);
		rv = -1;
	}

	if (config_protocol_get() != AS_HB_PROTOCOL_V1) {
		uint32_t max_cluster_size = 0;
		if (msg_max_cluster_size_get(msg, &max_cluster_size) != 0) {
			DEBUG(
			  "Received message without max cluster size from node "
			  "%" PRIx64,
			  src_nodeid);
			stats_error_count(AS_HB_ERR_NO_ANV_LENGTH);
			if (HB_IS_PROTOCOL_LEGACY()) {
				// Allow packet without max cluster size in v3
				// but not in v2. Will ease rolling upgrades if
				// we decide not to send max cluster size in hb
				// messages in the future.
				rv = -1;
			}
		} else {
			DETAIL(
			  "Received message with max cluster size %d from node "
			  "%" PRIx64,
			  max_cluster_size, src_nodeid);

			// Ignore the message if the max cluster size of the
			// incoming message does not match.
			if (max_cluster_size !=
			    g_config.paxos_max_cluster_size) {
				DEBUG(
				  "Received message with different max cluster "
				  "size form node "
				  "%" PRIx64,
				  src_nodeid);
				stats_error_count(
				  AS_HB_ERR_MAX_CLUSTER_SIZE_MISMATCH);
				rv = -1;
			} else {
				DETAIL(
				  "Received message with the same max cluster "
				  "size %d form node "
				  "%" PRIx64,
				  max_cluster_size, src_nodeid);
			}
		}
	}

	if (!HB_IS_MSG_LEGACY(msg) && type == AS_HB_MSG_TYPE_PULSE) {
		char* remote_cluster_id = NULL;

		if (msg_cluster_id_get(msg, &remote_cluster_id) != 0) {
			remote_cluster_id = "";
		}

		char cluster_id[AS_CLUSTER_ID_SZ];
		as_config_cluster_id_get(cluster_id);

		if (strcmp(remote_cluster_id, cluster_id) != 0) {
			rv = -1;
			DEBUG("Recieved message from a node with "
			      "different cluster id. Ignoring!");
		}
	}

	DETAIL("Received message of type %d from node %" PRIx64, type,
	       src_nodeid);

	return rv;
}

/**
 * Process incoming message to possibly update channel state.
 *
 * @param socket the socket on which the message is received.
 * @param event the message warpped around in a channel event.
 * @return 0 if the message can be further processed, -1 if the message should
 * be discarded.
 */
static int
channel_msg_event_process(cf_socket* socket, as_hb_channel_event* event)
{

	// Basic sanity check for the inbound message.
	if (channel_msg_sanity_check(event->msg) != 0) {
		DETAIL("Sanity check failed for message on fd %d", CSFD(socket));
		return -1;
	}

	int rv = -1;
	CHANNEL_LOCK();

	as_hb_channel channel;
	if (channel_get_channel(socket, &channel) < 0) {
		// This is a bug and should not happen. Be paranoid and
		// try fixing it ?
		WARNING("Received a message on an unregistered fd %d. "
			"Closing the fd.",
			CSFD(socket));
		channel_socket_close_queue(socket, false, true);
		rv = -1;
		goto Exit;
	}

	cf_node nodeid = event->nodeid;

	if (channel.nodeid != 0 && channel.nodeid != nodeid) {
		// The event nodeid does not match previously know event
		// id. Something seriously wrong here.
		WARNING("Received a message from node with incorrect "
			"nodeid. Expected %" PRIx64 " received %" PRIx64
			" on fd %d",
			channel.nodeid, nodeid, CSFD(socket));
		rv = -1;
		goto Exit;
	}

	// Update the last received time for this node
	channel.last_received = cf_getms();

	SHASH_PUT_OR_DIE(g_hb.channel_state.socket_to_channel, &socket, &channel,
			 "Error updating node %" PRIX64 " with fd %d", nodeid,
			 CSFD(socket));

	as_hb_endpoint node_endpoint;

	msg_endpoint_get(event->msg, &node_endpoint);

	cf_socket* existing_socket;
	int get_result =
	  SHASH_GET_OR_DIE(g_hb.channel_state.nodeid_to_socket, &nodeid,
			   &existing_socket, "Error reading from channel hash.");

	if (get_result == SHASH_ERR_NOTFOUND) {
		// Assoicate this socket with the node.
		channel_node_attach(socket, &channel, nodeid, &node_endpoint);
	} else if (existing_socket != socket) {

		// Somehow the other node and this node discovered each
		// other together both connected via two tcp connections.
		// Choose one and close the other.
		cf_socket* resolved = channel_socket_resolve(socket, existing_socket);

		if (!resolved) {
			DEBUG("Resolving between fd %d and %d failed. "
			      "Closing both connections.",
			      CSFD(socket), CSFD(existing_socket));

			// Resolution failed. Should not happen but there is a
			// window where the same node initiated two connections.
			// Close both connections and try again.
			channel_socket_close_queue(socket, false, true);
			channel_socket_close_queue(existing_socket, false, true);

			// Nothing wrong with the message. Let it through.
			rv = 0;
			goto Exit;
		}

		DEBUG("Resolved fd %d between redundant fd %d and %d for node "
		      "%" PRIx64,
		      CSFD(resolved), CSFD(socket), CSFD(existing_socket), nodeid);

		if (resolved == existing_socket) {
			// The node to socket mapping is correct, just close
			// this socket and this node will  still be connected to the
			// remote node. Do not raise any event for this closure.
			channel_socket_close_queue(socket, false, false);
		} else {

			// We need to close the existing socket. Disable
			// channel events because we make the node appear to be
			// not connected. Do not raise any event for this
			// closure.
			channel_socket_close_queue(existing_socket, false, false);
			// Assoicate this socket with the node.
			channel_node_attach(socket, &channel, nodeid,
					    &node_endpoint);
		}
	}

	rv = 0;

Exit:
	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Convert the M_TYPE_HEARTBEAT_V2 type info message to M_TYPE_HEARTBEAT info
 * massage.
 * @param socket the source socket
 * @param msg the incoming message
 * @return true if the message could be made compatible, else false.
 */
static bool
channel_msg_make_compatible(cf_socket* socket, msg* msg)
{
	as_hb_msg_type msg_type = -1;
	msg_type_get(msg, &msg_type);

	if (HB_IS_MSG_LEGACY(msg) && IS_MESH() &&
	    (msg_type == AS_HB_MSG_TYPE_INFO_REQUEST ||
	     msg_type == AS_HB_MSG_TYPE_INFO_REPLY)) {

		as_hb_channel channel;

		cf_node to_discover;
		msg_nodeid_get(msg, &to_discover);
		if (msg_type == AS_HB_MSG_TYPE_INFO_REQUEST) {
			msg_adjacency_set(msg, &to_discover, (size_t)1);
		} else {
			as_hb_mesh_info_reply reply;
			reply.nodeid = to_discover;
			msg_endpoint_get(msg, &reply.endpoint);

			if (msg_set_buf(msg, AS_HB_MSG_HB_DATA,
					(uint8_t*)&reply, sizeof(reply),
					MSG_SET_COPY) != 0) {
				CRASH("Error setting info reply list on msg.");
			}
		}

		// The node id, end point are not reliable, because mesh info
		// reply/requests used the nodeid field for the query node id
		// instead of their nodeids.
		if (channel_get_channel(socket, &channel) == 0) {
			if (channel.nodeid == 0) {
			}
			msg_set_uint64(msg, AS_HB_MSG_NODE, channel.nodeid);
			msg_set_uint32(
			  msg, AS_HB_MSG_ADDR,
			  as_hb_ipaddr_to_ipv4h(&channel.endpoint.addr));
			msg_set_uint32(msg, AS_HB_MSG_PORT,
				       channel.endpoint.port);
		} else {
			return false;
		}
	}
	return true;
}

/**
 * Read a message from a socket that has data.
 * @param socket the socket having data to be read.
 */
static void
channel_msg_read(cf_socket* socket)
{

	CHANNEL_LOCK();

	as_hb_channel_msg_read_status status;
	as_hb_channel channel;

	bool free_msg = true;

	msg* msg = hb_msg_get();

	if (channel_get_channel(socket, &channel) != 0) {
		// Would happen if the channel was closed in the same epoll oop.
		DEBUG("Error the channel does not exist for fd %d", CSFD(socket));
		goto Exit;
	}

	if (channel.is_multicast) {
		status = channel_multicast_msg_read(socket, msg);
	} else {
		status = channel_mesh_msg_read(socket, msg);
	}

	switch (status) {
		case AS_HB_CHANNEL_MSG_READ_SUCCESS: {
			break;
		}

		case AS_HB_CHANNEL_MSG_PARSE_FAIL: {
			DETAIL("unable to parse heartbeat message on fd %d",
			       CSFD(socket));
			stats_error_count(AS_HB_ERR_UNPARSABLE_MSG);
			goto Exit;
		}

		case AS_HB_CHANNEL_MSG_TYPE_FAIL: {
			DEBUG("Received message with different message type");
			// Consider this as protocol mismatch.
			stats_error_count(
			  AS_HB_ERR_HEARTBEAT_PROTOCOL_MISMATCH);
		}

		case AS_HB_CHANNEL_MSG_CHANNEL_FAIL:
		// Falling through
		default: {
			DEBUG("Could not read message from fd %d", CSFD(socket));
			if (!channel.is_multicast) {
				// Shut down only mesh socket.
				channel_socket_shutdown(socket);
			}
			goto Exit;
		}
	}

	// Transform the incoming legacy info message to the new
	// message.
	if (!channel_msg_make_compatible(socket, msg)) {
		WARNING("Received message without associated channel.");
		goto Exit;
	}

	as_hb_channel_event event;

	if (0 > msg_get_uint64(msg, AS_HB_MSG_NODE, &event.nodeid)) {
		// Node id missing from the message. Assume this message
		// to be corrupt.
		DEBUG("Message with invalid nodeid received on fd %d",
		      CSFD(socket));
		stats_error_count(AS_HB_ERR_NO_SRC_NODE);
		goto Exit;
	}

	event.msg = msg;
	event.type = AS_HB_CHANNEL_MSG_RECEIVED;
	memcpy(&event.peer_endpoint, &channel.endpoint,
	       sizeof(event.peer_endpoint));

	// Update hlc and store update message timestamp for the event.
	as_hlc_timestamp send_ts = 0;
	msg_send_ts_get(msg, &send_ts);
	as_hlc_timestamp_update(event.nodeid, send_ts, &event.msg_hlc_ts);

	// Process received message to update channel state.
	if (channel_msg_event_process(socket, &event) == 0) {
		// The message needs to be deliverd to the listeners. Prevent a
		// free.
		free_msg = false;
		channel_event_queue(&event);
	}

Exit:
	CHANNEL_UNLOCK();

	// release the message.
	if (free_msg) {
		hb_msg_return(msg);
	}
}

/**
 * Reduce function to remove faulty channels / nodes. Shutdown associated socket to
 * have channel tender cleanup.
 */
static int
channel_channels_tend_reduce(void* key, void* data, void* udata)
{
	cf_socket** socket = (cf_socket**)key;
	as_hb_channel* channel = (as_hb_channel*)data;

	if (channel->last_received + CHANNEL_NODE_READ_IDLE_TIMEOUT() <
	    cf_getms()) {
		// Shutdown associated socket if it is not a multicast socket.
		if (!channel->is_multicast) {
			DEBUG(
			  "Channel shutting down idle fd %d associated with "
			  "node %" PRIx64 ". Last received %" PRIu64 ".",
			  CSFD(*socket), channel->nodeid, channel->last_received);
			channel_socket_shutdown(*socket);
		}
	}

	return SHASH_OK;
}

/**
 * Tend channel specific node information to remove channels that are faulty (or
 * TODO: attached to misbehaving nodes).
 */
static void
channel_channels_tend()
{
	CHANNEL_LOCK();

	shash_reduce(g_hb.channel_state.socket_to_channel,
		     channel_channels_tend_reduce, NULL);

	CHANNEL_UNLOCK();
}

/**
 * Socket tending thread. Manages hearbeat receive as well.
 */
static void*
channel_tender(void* arg)
{

	DETAIL("Channel tender started.");
	while (CHANNEL_IS_RUNNING()) {
		cf_poll_event events[POLL_SZ];
		int nevents =
		  cf_poll_wait(g_hb.channel_state.poll, events, POLL_SZ,
			       MAX(config_hb_tx_interval_get() / 3, 1));

		DETAIL("Tending channel");

		if (nevents < 0) {
			// Legacy did not crash here. Retaining the same
			// behaviour.
			if (errno == EINTR) {
				continue;
			}
			WARNING("epoll_wait() returned %d ; errno = %d (%s)",
				nevents, errno, cf_strerror(errno));
		}

		for (int i = 0; i < nevents; i++) {
			cf_socket* socket = events[i].data;
			if (socket == g_hb.channel_state.listening_socket &&
			    IS_MESH()) {
				// Accept a new connection.
				channel_accept_connection();
			} else if (events[i].events &
				   (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {

				channel_socket_close_queue(socket, true, true);

			} else if (events[i].events & EPOLLIN) {
				// Read a message for the socket that is
				// ready.
				channel_msg_read(socket);
			}
		}

		// Tend channels to discard stale channels.
		channel_channels_tend();

		// Close queued up socket.
		channel_socket_close_pending();

		// Publish pending events. Should be outside channel lock.
		channel_event_publish_pending();

		DETAIL("Done tending channel");
	}

	DETAIL("Channel tender shut down.");
	return NULL;
}

/*---- Channel Public API ----*/

/**
 * Try and connect to a set of endpoints.
 */
static void
channel_mesh_channel_establish(as_hb_endpoint* endpoints, int endpoint_count)
{

	for (int i = 0; i < endpoint_count; i++) {
		char* endpoint_host_str;
		bool connected = false;
		if ((endpoint_host_str =
		       IPADDR_TO_STRING(&endpoints[i].addr)) == NULL) {
			WARNING("Error converting %" PRIx32 " to string",
				as_hb_ipaddr_to_ipv4h(&endpoints[i].addr));
			goto Next;
		}

		if (channel_endpoint_is_connected(&endpoints[i])) {
			DEBUG("Duplicate endpoint connect request. Ignoring "
			      "endpoint %s:%d",
			      endpoint_host_str, endpoints[i].port);
			goto Next;
		}

		cf_socket_cfg s;
		s.addr = (char*)endpoint_host_str;
		s.port = endpoints[i].port;
		s.type = SOCK_STREAM;

		DEBUG("Attempting to connect mesh host at %s:%d",
		      endpoint_host_str, endpoints[i].port);

		if (cf_socket_init_client(&s, CONNECT_TIMEOUT()) == 0) {
			cf_atomic_int_incr(
			  &g_stats.heartbeat_connections_opened);
			channel_socket_register(s.sock, false, false,
					    &endpoints[i]);
			connected = true;
		} else {
			DEBUG(
			  "Could not create heartbeat connection to node %s:%d",
			  endpoint_host_str, endpoints[i].port);
		}

	Next:
		if (!connected) {
			stats_error_count(AS_HB_ERR_MESH_CONNECT_FAIL);
		}
	}
}

/**
 * Disconnect a node from the channel list.
 * @param nodeid the nodeid of the node whose channel should be disconnected.
 * @return 0 if the node had a channel and was disconnected. -1 otherwise.
 */
static int
channel_node_disconnect(cf_node nodeid)
{
	int rv = -1;

	CHANNEL_LOCK();

	cf_socket* socket;
	if (channel_socket_get(nodeid, &socket) != 0) {
		// not found
		rv = -1;
		goto Exit;
	}

	DEBUG("Disconnecting the channel attached to node %" PRIx64, nodeid);

	channel_socket_close_queue(socket, false, true);

	rv = 0;

Exit:
	CHANNEL_UNLOCK();

	return rv;
}

/**
 * Register mesh listening socket.
 */
static void
channel_mesh_listening_sock_register(cf_socket* socket)
{
	g_hb.channel_state.listening_socket = socket;

	cf_poll_add_socket(g_hb.channel_state.poll, socket,
			   EPOLLIN | EPOLLERR | EPOLLHUP, socket);

	// We do not need a separate channel to cover this socket because IO will
	// not happen on this socket.
}

/**
 * Deregister mesh listening socket from epoll event.
 * @param socket the listening socket socket.
 */
static void
channel_mesh_listening_sock_deregister(cf_socket* socket)
{
	cf_poll_delete_socket(g_hb.channel_state.poll, socket);
}

/**
 * Register the multicast listening socket.
 * @param socket the listening socket.
 * @param endpoint the endpoint on which multicast io happens.
 */
static void
channel_multicast_listening_sock_register(cf_socket* socket,
					  as_hb_endpoint* endpoint)
{

	g_hb.channel_state.listening_socket = socket;
	// Create a new multicast channel.
	channel_socket_register(socket, true, false, endpoint);
}

/**
 * Deregister multicast listening socket from epoll event.
 * @param socket the listening socket socket.
 */
static void
channel_multicast_listening_sock_deregister(cf_socket* socket)
{
	cf_poll_delete_socket(g_hb.channel_state.poll, socket);
}

/**
 * Initialize the channel submodule.
 */
static void
channel_init()
{

	CHANNEL_LOCK();

	// Disable events till initialization is complete.
	channel_events_enabled_set(false);

	// Initialize unpublished event queue.
	if (!cf_queue_init(&g_hb.channel_state.events_queue,
			   sizeof(as_hb_channel_event),
			   AS_HB_CLUSTER_MAX_SIZE_SOFT, true)) {
		CRASH("Error creating channel event queue.");
	}

	// Initialize sockets to close queue.
	if (!cf_queue_init(&g_hb.channel_state.socket_close_queue,
			   sizeof(as_hb_channel_socket_close_entry),
			   AS_HB_CLUSTER_MAX_SIZE_SOFT, true)) {
		CRASH("Error creating fd close queue.");
	}

	// Initialize the nodeid to socket hash.
	if (SHASH_OK !=
	    shash_create(&g_hb.channel_state.nodeid_to_socket, cf_nodeid_shash_fn,
			 sizeof(cf_node), sizeof(cf_socket*),
			 AS_HB_CLUSTER_MAX_SIZE_SOFT, SHASH_CR_MT_BIGLOCK)) {
		CRASH("Error creating nodeid to fd hash.");
	}

	// Initialize the socket to channel state hash.
	if (SHASH_OK !=
	    shash_create(&g_hb.channel_state.socket_to_channel, as_hb_socket_hash_fn,
			 sizeof(cf_socket*), sizeof(as_hb_channel),
			 AS_HB_CLUSTER_MAX_SIZE_SOFT, SHASH_CR_MT_BIGLOCK)) {
		CRASH("Error creating fd to channel hash.");
	}

	g_hb.channel_state.status = AS_HB_STATUS_STOPPED;

	CHANNEL_UNLOCK();
}

/**
 * Start channel submodule. Kicks off the channel tending
 * thread.
 */
static void
channel_start()
{

	CHANNEL_LOCK();

	if (CHANNEL_IS_RUNNING()) {
		WARNING("HB channel already started");
		goto Exit;
	}

	// create the epoll socket.
	cf_poll_create(&g_hb.channel_state.poll);

	DEBUG("Created epoll fd %d", CEFD(g_hb.channel_state.poll));

	// Disable events till initialization is complete.
	channel_events_enabled_set(false);

	// Data structures have been initialized.
	g_hb.channel_state.status = AS_HB_STATUS_RUNNING;

	// Initialization complete enable events.
	channel_events_enabled_set(true);

	// Start the channel tender.
	if (0 != pthread_create(&g_hb.channel_state.channel_tender_tid, 0,
				channel_tender, &g_hb)) {
		CRASH("Could not create channel tender thread: %s",
		      cf_strerror(errno));
	}

Exit:

	CHANNEL_UNLOCK();
}

/**
 * Stop the channel submodule called on hb_stop.
 */
static void
channel_stop()
{

	if (!CHANNEL_IS_RUNNING()) {
		WARNING("HB channel already stopped");
		return;
	}

	DEBUG("Stopping the channel");

	// Unguarded state change but this shoud be ok.
	g_hb.channel_state.status = AS_HB_STATUS_SHUTTING_DOWN;

	// Wait for the channel tender thread to finish.
	pthread_join(g_hb.channel_state.channel_tender_tid, NULL);

	CHANNEL_LOCK();

	cf_vector sockets;
	cf_socket buff[shash_get_size(g_hb.channel_state.socket_to_channel)];
	cf_vector_init_smalloc(&sockets, sizeof(cf_socket*), (uint8_t*)buff,
			       sizeof(buff), VECTOR_FLAG_INITZERO);

	shash_reduce(g_hb.channel_state.socket_to_channel, channel_sockets_get_reduce,
		     &sockets);

	channel_sockets_close(&sockets);

	// Disable events.
	channel_events_enabled_set(false);

	cf_vector_destroy(&sockets);

	// Close epoll socket.
	cf_poll_destroy(g_hb.channel_state.poll);
	EFD(g_hb.channel_state.poll) = -1;

	// Disable the channel thread.
	g_hb.channel_state.status = AS_HB_STATUS_STOPPED;

	DEBUG("Channel Stopped");

	CHANNEL_UNLOCK();
}

/**
 * Send heartbeat protocol message retries in case of EAGAIN and EWOULDBLOCK
 * @param socket the socket to send the buffer over.
 * @param buff the data buffer.
 * @param buffer_length the number of bytes in the buffer to send.
 * @return 0 on successful send -1 on failure
 */
static int
channel_mesh_msg_send(cf_socket* socket, byte* buff, size_t buffer_length)
{

	CHANNEL_LOCK();

	int rv = -1;
	int retry = 0;
	const int max_retry = 3;
	size_t orig_size = buffer_length;
	cf_clock start = cf_getus();
	do {
		DETAIL(
		  "Sending mesh message on fd %d retry count:%d msg_size:%zu",
		  CSFD(socket), retry, buffer_length);

		int ret = cf_socket_send_to(socket, buff, buffer_length, 0, 0);
		if ((ret < 0) &&
		    ((errno != EAGAIN) || (errno != EWOULDBLOCK))) {
			break;
		} else if (ret > 0) {
			buff += ret;	  // incrementing buff pointer
			buffer_length -= ret; // decreasing msg_size to be sent
		}

		if (buffer_length > 0) {
			retry++;
			usleep(MESH_RW_TIMEOUT() / 3);
		} else {
			DETAIL("Sent mesh message fd %d retry "
			       "count:%d msg_size:%zu complete msg "
			       "sent",
			       CSFD(socket), retry, buffer_length);
			rv = 0;
			break;
		}
	} while (((start + MESH_RW_TIMEOUT()) > cf_getus()) &&
		 (retry < max_retry));

	if (buffer_length != 0) {
		if (buffer_length != orig_size) {
			WARNING(
			  "Fd %d incomplete mesh msg sent. %zu bytes left "
			  "out of %zu bytes.",
			  CSFD(socket), buffer_length, orig_size);
		} else {
			WARNING("Sending mesh message on fd %d failed : %s",
				CSFD(socket), cf_strerror(errno));
		}

		// Initiate a shutdown of the socket by blocking all read and write.
		channel_socket_shutdown(socket);
		rv = -1;
	}

	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Send heartbeat protocol message retries in case of EAGAIN and EWOULDBLOCK
 * @param socket the socket to send the buffer over.
 * @param buff the data buffer.
 * @param buffer_length the number of bytes in the buffer to send.
 * @return 0 on successful send -1 on failure
 */
static int
channel_multicast_msg_send(cf_socket* socket, byte* buff, size_t buffer_length)
{
	CHANNEL_LOCK();
	int rv = 0;
	DETAIL("Sending udp heartbeat to fd %d: msg size %zu", CSFD(socket),
	       buffer_length);

	int mtu = MTU();
	if (buffer_length > mtu) {
		DETAIL(
		  "MTU breach, sending udp heartbeat to fd %d: msg size %zu "
		  "mtu %d",
		  CSFD(socket), buffer_length, mtu);
		stats_error_count(AS_HB_ERR_MTU_BREACH);
	}

	cf_sock_addr dest;

	if (cf_sock_addr_from_host_port(config_hb_listen_addr_s_get(),
					config_hb_listen_port_get(),
					&dest) < 0) {
		DETAIL("Invalid hearbeat address %s:%d",
		       config_hb_listen_addr_s_get(),
		       config_hb_listen_port_get());
		rv = -1;
		goto Exit;
	}

	if (0 > cf_socket_send_to(socket, buff, buffer_length, 0, &dest)) {
		DETAIL("Multicast message send failed on fd %d %s", CSFD(socket),
		       cf_strerror(errno));
		rv = -1;
	}
Exit:
	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Inidicates if this msg requires compression.
 */
static bool
channel_msg_is_compression_required(msg* msg, int wire_size, int mtu)
{
	return !HB_IS_MSG_LEGACY(msg) &&
	       wire_size > MSG_COMPRESSION_THRESHOLD(mtu);
}

/**
 * Estimate the size of the buffer required to fill out the serialized message.
 * @param msg the input message.
 * @param mtu the underlying network mtu.
 * @return the size of the buffer required.
 */
static int
channel_msg_buffer_size_get(int wire_size, int mtu)
{
	return round_up_pow2(MAX(wire_size, compressBound(wire_size)));
}

/**
 * Fills the buffer with the serialized message.
 * @param original_msg the original message to serialize.
 * @param wire_size the message wire size.
 * @param mtu the underlying network mtu.
 * @param buffer the destination buffer.
 * @param buffer_len the buffer length.
 *
 * @return -1 on failure, length of the serialized message on success.
 */
static int
channel_msg_buffer_fill(msg* original_msg, int wire_size, int mtu,
			uint8_t* buffer, size_t buffer_len)
{

	int rv = -1;

	// This is output by msg_fillbuf. Using a separate variable so that we
	// do not lose the actual buffer length needed for compression later on.
	size_t msg_size = buffer_len;
	if (msg_fillbuf(original_msg, buffer, &msg_size) != 0) {
		rv = -1;
		goto Exit;
	}

	if (channel_msg_is_compression_required(original_msg, msg_size, mtu)) {

		// Compression is required.
		const size_t compressed_buffer_len = buffer_len;
		uint8_t* compressed_buffer = MSG_BUFF_ALLOC_OR_DIE(
		  compressed_buffer_len, "Error allocating memory size "
					 "%zu for compressing message",
		  compressed_buffer_len);

		size_t compressed_msg_size = compressed_buffer_len;
		int compress_rv =
		  compress2(compressed_buffer, &compressed_msg_size, buffer,
			    wire_size, Z_BEST_COMPRESSION);

		if (compress_rv == Z_BUF_ERROR) {
			// Compression result going to be larger than original
			// input buffer. Skip compression and try to send the
			// message as is.
			DETAIL(
			  "Skipping compression. Compressed size larger than"
			  " input size %zu.",
			  msg_size);
			rv = msg_size;
		} else {
			msg* temp_msg = hb_msg_get();

			msg_set_buf(temp_msg, AS_HB_MSG_COMPRESSED_PAYLOAD,
				    compressed_buffer, compressed_msg_size,
				    MSG_SET_COPY);
			msg_size = buffer_len;
			if (msg_fillbuf(temp_msg, buffer, &msg_size) == 0) {
				rv = msg_size;
			} else {
				rv = -1;
			}

			hb_msg_return(temp_msg);
		}

		MSG_BUFF_FREE(compressed_buffer, compressed_buffer_len);

	} else {
		rv = msg_size;
	}

Exit:
	return rv;
}

/**
 * Send a message to a destination node.
 */
static int
channel_msg_unicast(cf_node dest, msg* msg)
{
	size_t buffer_len = 0;
	uint8_t* buffer = NULL;
	if (!IS_MESH()) {
		// Can't send a unicast message in the multicast mode.
		WARNING("Ignoring sending unicast message in multicast mode.");
		return -1;
	}

	CHANNEL_LOCK();

	int rv = -1;
	cf_socket* connected_socket;

	if (channel_socket_get(dest, &connected_socket)) {
		DEBUG("Failing message send to disconnected node %" PRIx64,
		      dest);
		rv = -1;
		goto Exit;
	}

	// Read the message to a buffer.
	int mtu = MTU();
	int wire_size = msg_get_wire_size(msg);
	buffer_len = channel_msg_buffer_size_get(wire_size, mtu);
	buffer = MSG_BUFF_ALLOC_OR_DIE(
	  buffer_len, "Error allocating memory size %zu for sending "
		      "message to node %" PRIx64,
	  buffer_len, dest);

	size_t msg_size = 0;
	if ((msg_size = channel_msg_buffer_fill(msg, wire_size, mtu, buffer,
						buffer_len)) <= 0) {
		WARNING("Error writing message to buffer for node %" PRIx64,
			dest);
		rv = -1;
		goto Exit;
	}

	// Send over the buffer.
	rv = channel_mesh_msg_send(connected_socket, buffer, msg_size);

Exit:
	MSG_BUFF_FREE(buffer, buffer_len);
	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Shash reduce funtion to walk over the socket to channel hash and broadcast the
 * message in udata.
 */
static int
channel_msg_broadcast_reduce(void* key, void* data, void* udata)
{

	CHANNEL_LOCK();
	cf_socket** socket = (cf_socket**)key;
	as_hb_channel* channel = (as_hb_channel*)data;
	as_hb_channel_buffer_udata* buffer_udata =
	  (as_hb_channel_buffer_udata*)udata;

	if (!channel->is_multicast) {
		DETAIL("Broadcasting message of length %zu on channel %d "
		       "assigned to "
		       "node %" PRIx64,
		       buffer_udata->buffer_len, CSFD(*socket), channel->nodeid);
		if (channel_mesh_msg_send(*socket, buffer_udata->buffer,
					  buffer_udata->buffer_len) != 0) {
			stats_error_count(AS_HB_ERR_SEND_BROADCAST_FAIL);
		}
	} else {
		DETAIL("Broadcasting message of length %zu on channel %d",
		       buffer_udata->buffer_len, CSFD(*socket));
		if (channel_multicast_msg_send(*socket, buffer_udata->buffer,
					       buffer_udata->buffer_len) != 0) {
			stats_error_count(AS_HB_ERR_SEND_BROADCAST_FAIL);
		}
	}

	CHANNEL_UNLOCK();

	return SHASH_OK;
}

/**
 * Broadcast a message over all channels.
 */
static int
channel_msg_broadcast(msg* msg)
{

	CHANNEL_LOCK();

	int rv = -1;

	// Read the message to a buffer.
	int mtu = MTU();
	int wire_size = msg_get_wire_size(msg);
	size_t buffer_len = channel_msg_buffer_size_get(wire_size, mtu);
	uint8_t* buffer = MSG_BUFF_ALLOC_OR_DIE(
	  buffer_len,
	  "Error allocating memory size %zu for sending broadcast message.",
	  buffer_len);

	size_t msg_size = 0;
	if ((msg_size = channel_msg_buffer_fill(msg, wire_size, mtu, buffer,
						buffer_len)) <= 0) {
		WARNING("Error writing message to buffer for broadcast");
		rv = -1;
		goto Exit;
	}

	as_hb_channel_buffer_udata udata;
	udata.buffer = buffer;

	// Note this is the length of buffer to send.
	udata.buffer_len = msg_size;

	shash_reduce(g_hb.channel_state.socket_to_channel,
		     channel_msg_broadcast_reduce, &udata);

Exit:
	MSG_BUFF_FREE(buffer, buffer_len);
	CHANNEL_UNLOCK();
	return rv;
}

/**
 * Clear all channel state.
 */
static void
channel_clear()
{

	if (!CHANNEL_IS_STOPPED()) {
		WARNING(
		  "Attempted channel clear without stopping the channel.");
		return;
	}

	CHANNEL_LOCK();

	// Free the unpublished event queue.
	cf_queue_delete_all(&g_hb.channel_state.events_queue);

	// Delete nodeid to socket hash.
	shash_reduce_delete(g_hb.channel_state.nodeid_to_socket,
			    as_hb_delete_all_reduce, NULL);

	// Delete the socket_to_channel hash.
	shash_reduce_delete(g_hb.channel_state.socket_to_channel,
			    as_hb_delete_all_reduce, NULL);

	DETAIL("Cleared channel information.");
	CHANNEL_UNLOCK();
}

/**
 * Reduce function to dump channel node info to log file.
 */
static int
channel_dump_reduce(void* key, void* data, void* udata)
{

	cf_socket** socket = (cf_socket**)key;
	as_hb_channel* channel = (as_hb_channel*)data;

	INFO("HB Channel (%s): Node %" PRIx64 " Fd %d"
	     " Endpoint %s:%d Polarity %s Last Received %" PRIu64,
	     channel->is_multicast ? "multicast" : "mesh", channel->nodeid,
	     CSFD(*socket), IPADDR_TO_STRING(&channel->endpoint.addr),
	     channel->endpoint.port,
	     channel->is_inbound ? "inbound" : "outbound",
	     channel->last_received);

	return SHASH_OK;
}

/**
 * Dump channel state to logs.
 * @param verbose enables / disables verbose logging.
 */
static void
channel_dump(bool verbose)
{

	CHANNEL_LOCK();

	INFO("HB Channel Count %d",
	     shash_get_size(g_hb.channel_state.socket_to_channel));

	if (verbose) {
		shash_reduce(g_hb.channel_state.socket_to_channel,
			     channel_dump_reduce, NULL);
	}

	CHANNEL_UNLOCK();
}

/*----------------------------------------------------------------------------
 * Mesh submodule.
 *----------------------------------------------------------------------------*/

/**
 * Convert mesh status to a string.
 */
static const char*
mesh_node_status_string(as_hb_mesh_node_status status)
{
	static char* status_str[] = { "active", "pending", "inactive",
				      "endpoint-unknown" };

	if (status > AS_HB_MESH_NODE_ENDPOINT_UNKNOWN) {
		return "corrupted";
	}
	return status_str[status];
}

static void
mesh_tend_udata_capacity_ensure(as_hb_mesh_tend_reduce_udata* tend_reduce_udata,
				int mesh_node_count)
{
	// Ensure capacity for nodes to connect.
	if (tend_reduce_udata->to_connect_capacity < mesh_node_count) {

		uint32_t alloc_size =
		  round_up_pow2(mesh_node_count * sizeof(as_hb_endpoint));
		tend_reduce_udata->to_connect_capacity =
		  alloc_size / sizeof(as_hb_endpoint);

		tend_reduce_udata->to_connect =
		  tend_reduce_udata->to_connect != NULL
		    ? cf_realloc(tend_reduce_udata->to_connect, alloc_size)
		    : cf_malloc(alloc_size);

		if (tend_reduce_udata->to_connect == NULL) {
			CRASH("Error allocating endpoint space for "
			      "mesh tender.");
		}
	}
}

/**
 * Change the state of a mesh node. Note: memset the mesh_nodes to zero before
 * calling state chane for the first time.
 u */
static void
mesh_node_status_change(as_hb_mesh_node* mesh_node,
			as_hb_mesh_node_status new_status)
{
	as_hb_mesh_node_status old_status = mesh_node->status;
	mesh_node->status = new_status;

	if ((new_status != AS_HB_MESH_NODE_CHANNEL_ACTIVE &&
	     old_status == AS_HB_MESH_NODE_CHANNEL_ACTIVE) ||
	    mesh_node->last_status_updated == 0) {
		mesh_node->inactive_since = cf_getms();
	}
	mesh_node->last_status_updated = cf_getms();
	return;
}

/**
 * Update a mesh seed node to its real nodeid.
 * @param mesh_node the mesh seed node.
 * @param existing_node_key the hash key for the node.
 * @param nodeid the real nodeid.
 * @param new_status the new node status.
 */
static void
mesh_seed_node_real_nodeid_set(as_hb_mesh_node* mesh_node,
			       as_hb_mesh_node_key* existing_node_key,
			       cf_node nodeid,
			       as_hb_mesh_node_status new_status)
{
	MESH_LOCK();

	// Delete the entry with incorrect nodeid
	SHASH_DELETE_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			    existing_node_key,
			    "Error deleting mesh node for node %" PRIx64,
			    existing_node_key->nodeid);

	// Update the state of this mesh entry.
	mesh_node->nodeid = nodeid;
	mesh_node_status_change(mesh_node, new_status);

	as_hb_mesh_node_key new_key;
	new_key.nodeid = nodeid;
	new_key.is_real_nodeid = true;
	SHASH_PUT_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			 &new_key, mesh_node, "Error adding mesh node %" PRIx64,
			 nodeid);

	MESH_UNLOCK();

	DEBUG("Set real nodeid %" PRIx64 " for a seed node.", nodeid);
}

/**
 * Close mesh listning socket.
 */
static void
mesh_listening_socket_close()
{
	MESH_LOCK();
	INFO("Closing mesh heartbeat socket : %s:%d",
	     g_hb.mode_state.mesh_state.socket.addr,
	     g_hb.mode_state.mesh_state.socket.port);

	cf_socket_close(g_hb.mode_state.mesh_state.socket.sock);

	DEBUG("Closed mesh heartbeat socket");
	MESH_UNLOCK();
}

/**
 * Reduce function to copy mesh seed list on to the buffer.
 */
static int
mesh_seed_host_list_reduce(void* key, void* data, void* udata)
{

	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;
	cf_dyn_buf* db = (cf_dyn_buf*)udata;

	if (mesh_node->is_seed) {
		cf_dyn_buf_append_string(db,
					 "heartbeat.mesh-seed-address-port=");
		cf_dyn_buf_append_string(
		  db, IPADDR_TO_STRING(&mesh_node->endpoint.addr));
		cf_dyn_buf_append_char(db, ':');
		cf_dyn_buf_append_int(db, mesh_node->endpoint.port);
		cf_dyn_buf_append_char(db, ';');
	}

	return SHASH_OK;
}

/**
 * Populate the buffer with mesh seed list.
 */
static void
mesh_seed_host_list_get(cf_dyn_buf* db)
{
	if (!IS_MESH()) {
		return;
	}
	MESH_LOCK();

	shash_reduce(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
		     mesh_seed_host_list_reduce, db);

	MESH_UNLOCK();
}

/**
 * Stop the mesh module.
 */
static void
mesh_stop()
{

	if (!MESH_IS_RUNNING()) {
		WARNING("Mesh is already stopped.");
		return;
	}

	// Ungaurded state, but this should be ok.
	g_hb.mode_state.mesh_state.status = AS_HB_STATUS_SHUTTING_DOWN;

	// Wait for the channel tender thread to finish.
	pthread_join(g_hb.mode_state.mesh_state.mesh_tender_tid, NULL);

	MESH_LOCK();

	channel_mesh_listening_sock_deregister(
	  g_hb.mode_state.mesh_state.socket.sock);

	mesh_listening_socket_close();

	g_hb.mode_state.mesh_state.status = AS_HB_STATUS_STOPPED;

	MESH_UNLOCK();
}

/**
 * Compute the endpoint ipaddress to use to connect to a node. The order
 *   - resolve the mesh hostname to an ip address.
 *   - if that fails use the last computed endpoint.
 *   - if there is no last computed endpoint fail endpoint computation.
 *
 * @param mesh_node the mesh node
 * @return 0 on success. -1 if the mesh host name could not be resolved to a
 * valid ip address.
 */
static int
mesh_node_compute_endpoint(as_hb_mesh_node* mesh_node)
{

	int hostname_len = strnlen(mesh_node->mesh_host_name, HOST_NAME_MAX);

	if (hostname_len > 0 && hostname_len != HOST_NAME_MAX) {

		struct addrinfo* result = NULL;

		if (getaddrinfo(mesh_node->mesh_host_name, NULL, NULL,
				&result) == 0) {
			if (result) {
				// Pick the first ip address.
				as_hb_ipaddr_from_ipv4(
				  *(uint32_t*)&(
				    ((struct sockaddr_in*)result->ai_addr)
				      ->sin_addr),
				  &mesh_node->endpoint.addr);
			}
		} else {
			// Fall through and see if the last computed ip address
			// can be used.
		}

		if (result) {
			freeaddrinfo(result);
		}
	}

	char* endpoint_host_str = IPADDR_TO_STRING(&mesh_node->endpoint.addr);

	DETAIL("Resolved mesh node hostname %s to %s",
	       mesh_node->mesh_host_name,
	       endpoint_host_str != NULL ? endpoint_host_str : "unknown");

	return as_hb_ipaddr_is_specified(&mesh_node->endpoint.addr) ? 0 : -1;
}

/**
 * Determines if a mesh entry should be connected to or expired and deleted.
 */
static int
mesh_tend_reduce(void* key, void* data, void* udata)
{

	int rv = SHASH_OK;

	MESH_LOCK();

	cf_node nodeid = ((as_hb_mesh_node_key*)key)->nodeid;
	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;
	as_hb_mesh_tend_reduce_udata* tend_reduce_udata =
	  (as_hb_mesh_tend_reduce_udata*)udata;

	DETAIL("Tending mesh node %" PRIx64 " with status %s", nodeid,
	       mesh_node_status_string(mesh_node->status));

	if (mesh_node->status == AS_HB_MESH_NODE_CHANNEL_ACTIVE) {
		// The mesh node is connected. Skip.
		goto Exit;
	}

	cf_clock now = cf_getms();

	if (mesh_node->inactive_since + MESH_INACTIVE_TIMEOUT() <= now) {
		if (!mesh_node->is_seed) {
			DEBUG(
			  "Mesh forgetting node %" PRIx64
			  " because it could not be connected since %" PRIu64,
			  nodeid, mesh_node->inactive_since);

			rv = SHASH_REDUCE_DELETE;
			goto Exit;
		} else {
			// A seed node that we could not connect to for a while.
			DEBUG("Mesh seed node %" PRIx64
			      " could not be connected since %" PRIu64,
			      nodeid, mesh_node->inactive_since);
		}
	}

	if (mesh_node->status == AS_HB_MESH_NODE_ENDPOINT_UNKNOWN) {
		if (!mesh_node->is_seed &&
		    mesh_node->last_status_updated +
			MESH_ENDPOINT_UNKNOWN_TIMEOUT() >
		      now) {
			DEBUG("Mesh forgetting node %" PRIx64
			      " ipaddress/port undiscovered since %" PRIu64,
			      nodeid, mesh_node->last_status_updated);
			rv = SHASH_REDUCE_DELETE;
			goto Exit;
		}
	}

	if (mesh_node->status == AS_HB_MESH_NODE_CHANNEL_PENDING) {
		// The mesh node is being connected. Skip.

		if (mesh_node->last_status_updated + MESH_PENDING_TIMEOUT() >
		    now) {
			goto Exit;
		}

		// Flip to inactive if we have been in pending state for a long
		// time.
		mesh_node_status_change(mesh_node,
					AS_HB_MESH_NODE_CHANNEL_INACTIVE);
	}

	// Channel for this node is inactive. Create an endpoint and prompt the
	// channel submodule to connect to this node.

	// Compute the actual ipaddress and port for this mesh host.
	mesh_node_compute_endpoint(mesh_node);

	if (tend_reduce_udata->to_connect_count >=
	    tend_reduce_udata->to_connect_capacity) {
		// New nodes found but we are out of capacity. Ultra defensive
		// coding. This will never happen under the locks.
		WARNING("Skipping connecting to node %" PRIx64
			" Not enough memory allocated.",
			nodeid);
		goto Exit;
	}

	memcpy(
	  &tend_reduce_udata->to_connect[tend_reduce_udata->to_connect_count],
	  &mesh_node->endpoint, sizeof(as_hb_endpoint));
	tend_reduce_udata->to_connect_count++;

	// Flip to back to pending. Actually the channel establish call is
	// outside the reduce, however lets assume it will always happen.
	mesh_node_status_change(mesh_node, AS_HB_MESH_NODE_CHANNEL_PENDING);

Exit:

	MESH_UNLOCK();

	return rv;
}

/**
 * Tends the mesh host list, to discover and remove nodes. Should never
 * invoke a channel call while holding a mesh lock.
 */
static void*
mesh_tender(void* arg)
{
	DETAIL("Mesh tender started.");
	// Figure out which nodes need to be connected to.
	// collect nodes to connect to and remove dead nodes.
	as_hb_mesh_tend_reduce_udata tend_reduce_udata = { NULL, 0, 0 };

	while (IS_MESH() && MESH_IS_RUNNING()) {

		DETAIL("Tending mesh list.");

		MESH_LOCK();
		int mesh_node_count = shash_get_size(
		  g_hb.mode_state.mesh_state.nodeid_to_mesh_node);

		// Make sure the udata has enough capacity.
		mesh_tend_udata_capacity_ensure(&tend_reduce_udata,
						mesh_node_count);

		tend_reduce_udata.to_connect_count = 0;

		shash_reduce_delete(
		  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
		  mesh_tend_reduce, &tend_reduce_udata);

		MESH_UNLOCK();

		if (tend_reduce_udata.to_connect_count > 0) {
			// Try connecting the newer nodes.
			channel_mesh_channel_establish(
			  tend_reduce_udata.to_connect,
			  tend_reduce_udata.to_connect_count);
		}

		DETAIL("Done tending mesh list.");

		usleep(MESH_TEND_INTERVAL() * 1000);
	}

	if (tend_reduce_udata.to_connect) {
		cf_free(tend_reduce_udata.to_connect);
	}

	DETAIL("Mesh tender shut down.");
	return NULL;
}

/**
 * Reduce function to search for an endpoint in the mesh node hash.
 */
static int
mesh_endpoint_search_reduce(void* key, void* data, void* udata)
{

	as_hb_mesh_node_key* node_key = (as_hb_mesh_node_key*)key;
	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;
	as_hb_mesh_endpoint_reduce_udata* endpoint_reduce_udata =
	  (as_hb_mesh_endpoint_reduce_udata*)udata;

	if (memcmp(&mesh_node->endpoint, endpoint_reduce_udata->to_search,
		   sizeof(as_hb_endpoint)) == 0) {
		endpoint_reduce_udata->found = true;
		memcpy(endpoint_reduce_udata->matched_key, node_key,
		       sizeof(as_hb_mesh_node_key));
	}

	return SHASH_OK;
}

/**
 * Find a mesh node via its endpoint.
 *
 * @param endpoint the mesh endpoint.
 * @param key the output mesh key.
 * @return 0 on success, -1 on failure to find the endpoint.
 */
static int
mesh_node_endpoint_find(as_hb_endpoint* endpoint, as_hb_mesh_node_key* key)
{

	if (!as_hb_endpoint_is_specified(endpoint)) {
		// Null / empty endpoint.
		return -1;
	}

	// Linear search. This will in practice not be a very frequent
	// operation.
	as_hb_mesh_endpoint_reduce_udata udata;
	memset(&udata, 0, sizeof(udata));
	udata.to_search = endpoint;
	udata.matched_key = key;

	MESH_LOCK();

	shash_reduce(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
		     mesh_endpoint_search_reduce, &udata);

	MESH_UNLOCK();

	if (udata.found) {
		return 0;
	}

	return -1;
}

/**
 * Indicates if a give node is discovered.
 * @param nodeid the input nodeid.
 * @return true on success, false on failure.
 */
static bool
mesh_node_is_discovered(cf_node nodeid)
{

	if (nodeid == config_self_nodeid_get()) {
		// Assume this node knows itself.
		return true;
	}

	bool rv = false;

	as_hb_mesh_node_key key;
	key.is_real_nodeid = true;
	key.nodeid = nodeid;

	as_hb_mesh_node mesh_node;
	MESH_LOCK();
	if (SHASH_GET_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			     &key, &mesh_node,
			     "Error getting mesh information for node %" PRIX64,
			     nodeid) == SHASH_OK) {
		rv = true;
	} else {
		// The node not found.
		rv = false;
	}

	MESH_UNLOCK();
	return rv;
}

/**
 * Get the mesh node associated with this node.
 * @param nodeid the nodeid to search for.
 * @param is_real_nodeid indicates if the query is for a real or fake nodeid.
 * @param mesh_node the output mesh node.
 * @return 0 on success -1 if there is mesh node attached.
 */
static int
mesh_node_get(cf_node nodeid, bool is_real_nodeid, as_hb_mesh_node* mesh_node)
{
	int rv = -1;

	as_hb_mesh_node_key key;
	key.is_real_nodeid = is_real_nodeid;
	key.nodeid = nodeid;

	MESH_LOCK();

	if (SHASH_GET_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			     &key, mesh_node,
			     "Error getting mesh information for node %" PRIX64,
			     nodeid) == SHASH_OK) {
		DETAIL("Found existing mesh node for %" PRIx64, nodeid);
		rv = 0;
	} else {
		// The node not found.
		DETAIL("No mesh node found for %" PRIx64, nodeid);
		rv = -1;
	}

	MESH_UNLOCK();
	return rv;
}

/**
 * Handle the event when the channel reports a node as disconnected.
 */
static void
mesh_channel_on_node_disconnect(as_hb_channel_event* event)
{
	MESH_LOCK();

	as_hb_mesh_node mesh_node;
	if (mesh_node_get(event->nodeid, true, &mesh_node) != 0) {
		// Again should not happen in practice. But not really bad.
		DEBUG("Unknown mesh node disconnected %" PRIx64, event->nodeid);
		goto Exit;
	}

	DEBUG("Mesh setting node %" PRIx64
	      " status as inactive on loss of channel.",
	      event->nodeid);

	// Mark this node inactive and move on. Mesh tender should remove this
	// node if this is a non seed node and has been inactive for a
	// while.
	mesh_node_status_change(&mesh_node, AS_HB_MESH_NODE_CHANNEL_INACTIVE);

	as_hb_mesh_node_key node_key;
	memset(&node_key, 0, sizeof(node_key));
	node_key.is_real_nodeid = true;
	node_key.nodeid = event->nodeid;

	// Update the mesh entry.
	SHASH_PUT_OR_DIE(
	  g_hb.mode_state.mesh_state.nodeid_to_mesh_node, &node_key, &mesh_node,
	  "Error updating mesh node entry for %" PRIx64 " on loss of channel.",
	  event->nodeid);

Exit:
	MESH_UNLOCK();
}

/**
 * Indicates if a mesh node is upto date and active.
 * This means
 * a. A mesh entry for the source nodeid exists.
 * b. The mesh node's status is active
 * c. The event's endpoint, message source endpoint and the endpoint in the node
 * match.
 */
static bool
mesh_node_is_uptodate_active(as_hb_channel_event* event)

{
	MESH_LOCK();

	bool rv = false;
	as_hb_mesh_node mesh_node;

	bool nodeid_entry_exists =
	  mesh_node_get(event->nodeid, true, &mesh_node) == 0;

	if (!nodeid_entry_exists ||
	    mesh_node.status != AS_HB_MESH_NODE_CHANNEL_ACTIVE) {
		rv = false;
		goto Exit;
	}

	as_hb_endpoint msg_endpoint;
	msg_endpoint_get(event->msg, &msg_endpoint);

	if (as_hb_endpoint_is_specified(&event->peer_endpoint)) {
		if (as_hb_endpoint_cmp(&msg_endpoint, &event->peer_endpoint) !=
		    0) {
			// Peer and message endpoints differ. Happens if the
			// seed ip uses a different interface from the remote
			// peer's hb ip.
			rv = false;
			goto Exit;
		}
	}

	// Check that the message and the mesh node endpoints match.
	rv = as_hb_endpoint_cmp(&msg_endpoint, &mesh_node.endpoint) == 0;

Exit:
	MESH_UNLOCK();
	return rv;
}

/**
 * Check and fix the case where we received a self incoming message probably
 * because one of our non loop back itnerfaces was used as a seed address.
 *
 * @return true if this message is a self message, false otherwise.
 */
static bool
mesh_node_check_fix_self_msg(as_hb_channel_event* event)
{
	if (event->nodeid == config_self_nodeid_get()) {
		// Handle self message. Will happen if the seed node address on
		// this node does not match the listen / publish address.
		as_hb_mesh_node_key existing_node_key;
		if (mesh_node_endpoint_find(&event->peer_endpoint,
					    &existing_node_key) == 0) {
			MESH_LOCK();
			SHASH_DELETE_OR_DIE(
			  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			  &existing_node_key, "Error removing self "
					      "mesh entry with node id "
					      "%" PRIx64,
			  existing_node_key.nodeid);

			INFO("Removed self mesh "
			     "entry with  address %s:%d",
			     IPADDR_TO_STRING(&event->peer_endpoint.addr),
			     event->peer_endpoint.port);
			MESH_UNLOCK();
		}
		return true;
	}
	return false;
}

/**
 * See if a new non seed mesh host entry needs to be added.
 * @return true if a new entry was added. false otherwise.
 */
static bool
mesh_node_try_add_new(as_hb_channel_event* event)
{
	MESH_LOCK();

	bool rv = false;
	as_hb_mesh_node existing_mesh_node;

	bool nodeid_entry_exists =
	  mesh_node_get(event->nodeid, true, &existing_mesh_node) == 0;

	as_hb_endpoint remote_endpoint;
	msg_endpoint_get(event->msg, &remote_endpoint);

	as_hb_mesh_node_key existing_node_key;
	if (nodeid_entry_exists ||
	    mesh_node_endpoint_find(&remote_endpoint, &existing_node_key) ==
	      0) {
		// Existing mesh node entry.
		rv = false;
		goto Exit;
	}

	// This is a new node the mesh subsystem has not yet
	// seen. Will happen if the other node connected to this node.
	as_hb_mesh_node new_node;
	memset(&new_node, 0, sizeof(new_node));

	new_node.nodeid = event->nodeid;
	new_node.is_seed = false;

	char* endpoint_host_str;
	// Copy the ip address itself into the mesh host name.
	if ((endpoint_host_str = IPADDR_TO_STRING(&remote_endpoint.addr)) !=
	    NULL) {
		strcpy(new_node.mesh_host_name, endpoint_host_str);
	} else {
		new_node.mesh_host_name[0] = 0;
	}

	memcpy(&new_node.endpoint, &remote_endpoint, sizeof(as_hb_endpoint));

	mesh_node_status_change(&new_node, AS_HB_MESH_NODE_CHANNEL_ACTIVE);

	as_hb_mesh_node_key new_key = { true, new_node.nodeid };

	SHASH_PUT_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			 &new_key, &new_node, "Error adding mesh node %" PRIx64,
			 event->nodeid);

	rv = true;

	DEBUG("Added new mesh non seed entry with nodeid %" PRIx64
	      " and endpoint %s:%d",
	      new_node.nodeid, IPADDR_TO_STRING(&new_node.endpoint.addr),
	      new_node.endpoint.port);

Exit:
	MESH_UNLOCK();
	return rv;
}

/**
 * See if an incoming message cause a redundant / conflict mesh entry and fix
 * the issue.
 */
static void
mesh_node_fix_conflict(as_hb_channel_event* event)
{
	MESH_LOCK();

	as_hb_mesh_node existing_mesh_node;

	if (mesh_node_get(event->nodeid, true, &existing_mesh_node) != 0) {
		goto Exit;
	}

	as_hb_mesh_node_key existing_node_key = { true, event->nodeid };
	as_hb_mesh_node_key existing_endpoint_key;
	if (mesh_node_endpoint_find(&existing_mesh_node.endpoint,
				    &existing_endpoint_key) == 0) {
		if (existing_node_key.is_real_nodeid == true &&
		    existing_endpoint_key.is_real_nodeid == false) {
			// The seed node's nodeid has not yet been updated,
			// however we have added a non-seed entry for the same
			// node via mesh discovery. The non-seed entry is
			// redundant. Delete it and proceed to update the seed
			// node.
			SHASH_DELETE_OR_DIE(
			  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			  &existing_node_key, "Error removing redundant "
					      "mesh entry for node "
					      "%" PRIx64,
			  existing_node_key.nodeid);

			DEBUG("Removed redundant mesh "
			      "entry for node %" PRIx64,
			      existing_node_key.nodeid);
		}
	}

Exit:
	MESH_UNLOCK();
}

/**
 * Update mesh node status based on an incmoing message.
 */
static void
mesh_node_data_update(as_hb_channel_event* event)
{
	MESH_LOCK();
	as_hb_mesh_node existing_mesh_node;
	as_hb_mesh_node_key existing_node_key;

	as_hb_endpoint msg_endpoint;
	msg_endpoint_get(event->msg, &msg_endpoint);

	// Search by endpoint at first to locate the exact mesh node.
	if (mesh_node_endpoint_find(&event->peer_endpoint,
				    &existing_node_key) == 0) {

		mesh_node_get(existing_node_key.nodeid,
			      existing_node_key.is_real_nodeid,
			      &existing_mesh_node);

		if (existing_mesh_node.is_seed) {

			// Update the endpoint to be the message endpoint if the
			// seed ip and the published ip differ
			if (as_hb_endpoint_cmp(&existing_mesh_node.endpoint,
					       &msg_endpoint)) {
				INFO("Updating mesh seed endpoint address from "
				     "%s:%d to %s:%d",
				     IPADDR_TO_STRING(
				       &existing_mesh_node.endpoint.addr),
				     existing_mesh_node.endpoint.port,
				     IPADDR_TO_STRING(&msg_endpoint.addr),
				     msg_endpoint.port);
			}

			// Remove the conflicting node
			as_hb_mesh_node_key conflicting_node_key = {
				true, event->nodeid
			};

			SHASH_DELETE_OR_DIE(
			  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			  &conflicting_node_key, "Error removing redundant "
						 "mesh entry for node "
						 "%" PRIx64,
			  conflicting_node_key.nodeid);

			// Update the ip address.
			memcpy(&existing_mesh_node.endpoint, &msg_endpoint,
			       sizeof(msg_endpoint));

			// Update the mesh hash key to have real nodeid.
			mesh_seed_node_real_nodeid_set(
			  &existing_mesh_node, &existing_node_key,
			  event->nodeid, AS_HB_MESH_NODE_CHANNEL_ACTIVE);

			goto Exit;
		}
	} else {
		// Search by nodeid
		existing_node_key.is_real_nodeid = true;
		existing_node_key.nodeid = event->nodeid;

		if (mesh_node_get(existing_node_key.nodeid,
				  existing_node_key.is_real_nodeid,
				  &existing_mesh_node) != 0) {
			goto Exit;
		}

		// Actual update will happen in the common
		// update path below.
	}

	// Update the endpoint to be the message endpoint.
	memcpy(&existing_mesh_node.endpoint, &msg_endpoint,
	       sizeof(msg_endpoint));

	// Update status to active.
	mesh_node_status_change(&existing_mesh_node,
				AS_HB_MESH_NODE_CHANNEL_ACTIVE);

	SHASH_PUT_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			 &existing_node_key, &existing_mesh_node,
			 "Error updating mesh node %" PRIx64
			 " status to active",
			 event->nodeid);

Exit:
	MESH_UNLOCK();
}

/**
 * Update mesh node status on receiving a message. Recepit of a message implies
 * the mesh node is active. If the mesh does not have an entry for the message
 * source node, a new mesh host entry is added. This will happen if the source
 * node initiated a new mesh connection and sent its first heartbeat. Conflits
 * (multiple entries for the same nodeid) will be resolved and node data will be
 * updated.
 */
static bool
mesh_node_on_msg_update(as_hb_channel_event* event)
{

	if (mesh_node_check_fix_self_msg(event)) {
		// Message from self, can be ignored.
		return false;
	}

	if (mesh_node_is_uptodate_active(event)) {
		// Message for an upto date and active mesh node.The most common
		// case.
		return true;
	}

	if (mesh_node_try_add_new(event)) {
		// Message for a new mesh node
		return true;
	}

	// Check and fix conflicting entries for the same node.
	mesh_node_fix_conflict(event);

	// Update the mesh node.
	mesh_node_data_update(event);

	return true;
}

/**
 * Send a info reply in reply to an info request.
 * @param dest the destination node to send the info reply to.
 * @param reply array of node ids and endpoints
 * @param reply_count the count of replies.
 */
static void
mesh_nodes_send_info_reply(cf_node dest, as_hb_mesh_info_reply* reply,
			   size_t reply_count)
{

	// Create the discover message.
	msg* msg = hb_info_msg_init(AS_HB_MSG_TYPE_INFO_REPLY);

	// Set the reply.
	msg_info_reply_set(msg, reply, reply_count);

	DEBUG("Sending info reply to node %" PRIx64, dest);

	// Send the info reply.
	if (channel_msg_unicast(dest, msg) != 0) {
		DEBUG("Error sending info reply message to node %" PRIx64,
		      dest);
		stats_error_count(AS_HB_ERR_SEND_INFO_REPLY_FAIL);
	}

	hb_msg_return(msg);
}

/**
 * Initialize the info request msg buffer
 */
static msg*
hb_info_msg_init(as_hb_msg_type msg_type)
{
	msg* msg = hb_msg_get();
	msg_src_fields_fill(msg);
	msg_type_set(msg, msg_type);
	return msg;
}

/**
 * Send a info request for all undiscovered nodes.
 * @param dest the destination node to send the discover message to.
 * @param to_discover array of node ids to discover.
 * @param to_discover_count the count of nodes in the array.
 */
static void
mesh_nodes_send_info_request(msg* in_msg, cf_node dest, cf_node* to_discover,
			     size_t to_discover_count)
{
	if (HB_IS_MSG_LEGACY(in_msg)) {
		// Heartbeat version v2 expects only one info request at a time.
		for (int i = 0; i < to_discover_count; i++) {
			// Create the discover message.
			msg* info_req =
			  hb_info_msg_init(AS_HB_MSG_TYPE_INFO_REQUEST);

			// Set the node to discover.
			msg_set_uint64(info_req, AS_HB_MSG_NODE,
				       to_discover[i]);

			DEBUG("Sending info request to node %" PRIx64, dest);

			// Send the info request.
			if (channel_msg_unicast(dest, info_req) != 0) {
				DEBUG("Error sending info request message to "
				      "node %" PRIx64,
				      dest);
				stats_error_count(AS_HB_ERR_SEND_INFO_REQ_FAIL);
			}
			hb_msg_return(info_req);
		}

	} else {
		// Create the discover message.
		msg* info_req = hb_info_msg_init(AS_HB_MSG_TYPE_INFO_REQUEST);

		// Set the list of nodes to discover.
		msg_adjacency_set(info_req, to_discover, to_discover_count);

		DEBUG("Sending info request to node %" PRIx64, dest);

		// Send the info request.
		if (channel_msg_unicast(dest, info_req) != 0) {
			DEBUG(
			  "Error sending info request message to node %" PRIx64,
			  dest);
			stats_error_count(AS_HB_ERR_SEND_INFO_REQ_FAIL);
		}
		hb_msg_return(info_req);
	}
}

/**
 * Handle an incoming pulse message to discover new neighbours.
 */
static void
mesh_channel_on_pulse(msg* msg)
{
	cf_node* adj_list;
	size_t adj_length;

	cf_node source;

	// Channel has validated the source. Don't bother checking here.
	msg_nodeid_get(msg, &source);
	if (msg_adjacency_get(msg, &adj_list, &adj_length) != 0) {
		// Adjacency list absent.
		WARNING("Received message from %" PRIx64
			" without adjacency list.",
			source);
		return;
	}

	cf_node new_nodes[adj_length];
	size_t num_new_nodes = 0;

	MESH_LOCK();

	// Try and discover new nodes from this message's adjacency list.
	for (int i = 0; i < adj_length; i++) {
		if (!mesh_node_is_discovered(adj_list[i])) {

			DEBUG("Discovered new mesh node %" PRIx64, adj_list[i]);

			new_nodes[num_new_nodes++] = adj_list[i];

			as_hb_mesh_node new_node;
			memset(&new_node, 0, sizeof(new_node));
			new_node.nodeid = adj_list[i];
			new_node.is_seed = false;
			mesh_node_status_change(
			  &new_node, AS_HB_MESH_NODE_ENDPOINT_UNKNOWN);

			as_hb_mesh_node_key new_key;
			new_key.is_real_nodeid = true;
			new_key.nodeid = adj_list[i];

			// Add as a new node
			SHASH_PUT_OR_DIE(
			  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			  &new_key, &new_node,
			  "Error adding new mesh non seed node %" PRIx64,
			  source);
		}
	}

	MESH_UNLOCK();

	// Discover these nodes outside a lock.
	if (num_new_nodes) {
		mesh_nodes_send_info_request(msg, source, new_nodes,
					     num_new_nodes);
	}
}

/**
 * Handle and incoming info message.
 */
static void
mesh_channel_on_info_request(msg* msg)
{

	cf_node* query_nodeids;
	size_t query_count;

	cf_node source;
	msg_nodeid_get(msg, &source);

	if (msg_adjacency_get(msg, &query_nodeids, &query_count) != 0) {
		WARNING("Got an info request without query nodes from "
			"%" PRIx64,
			source);
		stats_error_count(AS_HB_ERR_NO_NODE_REQ);
		return;
	}

	as_hb_mesh_info_reply reply[query_count];
	size_t reply_count = 0;

	MESH_LOCK();

	DEBUG("Preparing a reply for: %zu", query_count);
	for (int i = 0; i < query_count; i++) {
		as_hb_mesh_node mesh_node;

		DEBUG("Mesh received info request for node %" PRIx64,
		      query_nodeids[i]);

		if (mesh_node_get(query_nodeids[i], true, &mesh_node) == 0) {
			if (mesh_node.status !=
			    AS_HB_MESH_NODE_ENDPOINT_UNKNOWN) {

				ASSERT(as_hb_ipaddr_is_specified(
					 &mesh_node.endpoint.addr),
				       "The endpoint should have been known "
				       "for mesh node %" PRIx64,
				       query_nodeids[i]);

				reply[reply_count].nodeid = query_nodeids[i];

				memcpy(&reply[reply_count].endpoint,
				       &mesh_node.endpoint,
				       sizeof(as_hb_endpoint));

				reply_count++;
			}
		}
	}

	MESH_UNLOCK();

	// Send the reply
	if (reply_count > 0) {
		mesh_nodes_send_info_reply(source, reply, reply_count);
	}
}

/**
 * Handle an incoming info reply.
 */
static void
mesh_channel_on_info_reply(msg* msg)
{

	as_hb_mesh_info_reply* reply = NULL;
	size_t reply_count = 0;
	cf_node source = 0;
	msg_nodeid_get(msg, &source);
	if (msg_info_reply_get(msg, &reply, &reply_count) != 0 ||
	    reply_count == 0) {
		WARNING("Got an info reply from without "
			"query nodes "
			"from %" PRIx64,
			source);
		stats_error_count(AS_HB_ERR_NO_NODE_REPLY);
		return;
	}

	MESH_LOCK();

	for (int i = 0; i < reply_count; i++) {
		// Search by endpoint to ensure that we do not hit an unknown
		// seed node again.
		as_hb_mesh_node_key key;
		if (mesh_node_endpoint_find(&reply[i].endpoint, &key) == 0) {

			if (key.is_real_nodeid) {
				if (key.nodeid != reply[i].nodeid) {

					// This is a bad case basically we see
					// two nodeids with same endpoint.
					char* endpoint_host_str =
					  IPADDR_TO_STRING(
					    &reply[i].endpoint.addr);
					WARNING("Discovered two "
						"nodes "
						"%" PRIx64 " and %" PRIx64
						" having same ip %s "
						"and port "
						"%d",
						key.nodeid, reply[i].nodeid,
						endpoint_host_str != NULL
						  ? endpoint_host_str
						  : "unknown",
						reply[i].endpoint.port);
				}

				// The found node was discovered via an incoming
				// pulse. Basically the other node discovered us
				// and sent an heartbeat before we got back a
				// reply.
			} else {

				// Found node is a seed node and we had not
				// discovered its nodeid yet. Now we do hence
				// switch entry to real nodeid.
				as_hb_mesh_node seed_mesh_node;
				if (mesh_node_get(key.nodeid,
						  key.is_real_nodeid,
						  &seed_mesh_node) != 0) {
					// Should never happen in practice.
					WARNING("Lost seed node with "
						"fake "
						"nodeid %" PRIx64,
						key.nodeid);
					continue;
				}

				mesh_seed_node_real_nodeid_set(
				  &seed_mesh_node, &key, reply[i].nodeid,
				  seed_mesh_node.status);
			}
		} else {
			as_hb_mesh_node existing_node;
			// Potentially a discovered node with endpoint unknown
			// previously. Update the endpoint.
			if (mesh_node_get(reply[i].nodeid, true,
					  &existing_node) != 0) {
				// Somehow the node was removed from the mesh
				// hash. Maybe a timeout.
				continue;
			}

			// Update the endpoint.
			memcpy(&existing_node.endpoint, &reply[i].endpoint,
			       sizeof(as_hb_endpoint));

			// Update the state of this node.
			if (existing_node.status ==
			    AS_HB_MESH_NODE_ENDPOINT_UNKNOWN) {
				mesh_node_status_change(
				  &existing_node,
				  AS_HB_MESH_NODE_CHANNEL_INACTIVE);
			}

			as_hb_mesh_node_key new_key;
			new_key.is_real_nodeid = true;
			new_key.nodeid = reply[i].nodeid;

			// Update the hash.
			SHASH_PUT_OR_DIE(
			  g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			  &new_key, &existing_node,
			  "Error updating endpoint for node "
			  "%" PRIx64,
			  reply[i].nodeid);
		}
	}

	MESH_UNLOCK();
}

/**
 * Handle the case when a message is received on a channel.
 */
static void
mesh_channel_on_msg_rcvd(as_hb_channel_event* event)
{

	// Update the source mesh node status.
	mesh_node_on_msg_update(event);

	as_hb_msg_type msg_type;
	msg_type_get(event->msg, &msg_type);

	switch (msg_type) {
		case AS_HB_MSG_TYPE_PULSE:
			// A pulse message. Try and discover new nodes.
			mesh_channel_on_pulse(event->msg);
			break;
		case AS_HB_MSG_TYPE_INFO_REQUEST:
			// Send back an info reply.
			mesh_channel_on_info_request(event->msg);
			break;
		case AS_HB_MSG_TYPE_INFO_REPLY:
			// Update the list of mesh nodes, if this is an
			// undiscovered node.
			mesh_channel_on_info_reply(event->msg);
			break;
		default:
			WARNING("Recieved a message of unknown type from.");
			// Ignore other messages.
			break;
	}
}

/**
 * Generate a fake but unique nodeid for a remote node whose nodeid is
 * unknown.
 * @param new_node the new seed node.
 */
static void
mesh_seed_node_add(as_hb_mesh_node* new_node)
{
	MESH_LOCK();

	uint32_t ipv4_addr = as_hb_ipaddr_to_ipv4h(&new_node->endpoint.addr);

	as_hb_mesh_node_key new_key;
	new_key.nodeid = 0;
	new_key.is_real_nodeid = false;

	// Ensure the generate id is unique.
	as_hb_mesh_node mesh_node = { 0 };
	do {

		memcpy(&new_key.nodeid, &ipv4_addr, sizeof(ipv4_addr));
		memcpy(((byte*)&new_key.nodeid) + sizeof(ipv4_addr),
		       &new_node->endpoint.port, sizeof(uint16_t));

		// increment the ip address, that willbe tried if this address
		// is not unique.
		ipv4_addr++;

	} while (mesh_node_get(new_key.nodeid, false, &mesh_node) == 0);

	char* endpoint_host_str = IPADDR_TO_STRING(&new_node->endpoint.addr);
	DETAIL("Generated dummy nodeid %" PRIx64 " for mesh seed host %s:%d",
	       new_key.nodeid,
	       endpoint_host_str != NULL ? endpoint_host_str : "unknown",
	       new_node->endpoint.port);

	// Add as a new node
	SHASH_PUT_OR_DIE(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			 &new_key, new_node,
			 "Error adding new mesh seed node %s:%d",
			 endpoint_host_str, new_node->endpoint.port);

	MESH_UNLOCK();
}

/*---- Mesh public API ----*/

/**
 * Add a host / port to the mesh seed list.
 * @param host the seed node hostname / ip address
 * @param port the seed node port.
 * @return SHASH_OK, SHASH_ERR, SHASH_ERR_FOUND.
 */
static int
mesh_tip(char* host, int port)
{
	MESH_LOCK();

	int rv = SHASH_ERR;

	as_hb_mesh_node new_node;
	memset(&new_node, 0, sizeof(new_node));
	mesh_node_status_change(&new_node, AS_HB_MESH_NODE_CHANNEL_INACTIVE);

	// Resove the ipaddress of the new tip.
	strncpy(new_node.mesh_host_name, host, sizeof(new_node.mesh_host_name));
	new_node.endpoint.port = port;
	new_node.is_seed = true;

	if (mesh_node_compute_endpoint(&new_node) != 0) {
		WARNING("Error resolving ip address for mesh host %s:%d", host,
			port);
		rv = SHASH_ERR;
		goto Exit;
	}

	// Check if this node itself is the seed node.
	if ((as_hb_ipaddr_cmp(&new_node.endpoint.addr,
			      config_hb_listen_addr_get()) == 0 &&
	     new_node.endpoint.port == config_hb_listen_port_get()) ||
	    (as_hb_ipaddr_cmp(&new_node.endpoint.addr,
			      config_hb_publish_addr_get()) == 0 &&
	     new_node.endpoint.port == config_hb_publish_port_get())) {
		WARNING("Ignoring adding self %s:%d as mesh seed ", host, port);
		rv = SHASH_ERR_FOUND;
		goto Exit;
	}

	// Check if we already know about this node.
	as_hb_mesh_node_key existing_node_key;
	if (mesh_node_endpoint_find(&new_node.endpoint, &existing_node_key) ==
	    0) {
		as_hb_mesh_node existing_node;
		// If the node is not already a seed node update the
		// node
		if (mesh_node_get(existing_node_key.nodeid,
				  existing_node_key.is_real_nodeid,
				  &existing_node) == 0) {

			if (existing_node.is_seed) {
				WARNING("Mesh host %s:%d already in "
					"mesh seed list",
					host, port);
				rv = SHASH_ERR_FOUND;
				goto Exit;
			} else {
				INFO("Mesh non seed host %s:%d already in "
				     "mesh "
				     "seed list. Promoting to seed node.",
				     host, port);

				existing_node.is_seed = true;
				SHASH_PUT_OR_DIE(g_hb.mode_state.mesh_state
						   .nodeid_to_mesh_node,
						 &existing_node.nodeid,
						 &existing_node,
						 "Error allocating space for "
						 "mesh tip node %s:%d",
						 host, port);
				rv = SHASH_OK;
				goto Exit;
			}
		}
	}

	mesh_seed_node_add(&new_node);

	DEBUG("Added new mesh seed %s:%d", host, port);
	rv = SHASH_OK;

Exit:
	MESH_UNLOCK();
	return rv;
}

/**
 * Handle a channel event on an endpoint.
 */
static void
mesh_channel_event_process(as_hb_channel_event* event)
{

	// Skip if we are not in mesh mode.
	if (!IS_MESH()) {
		return;
	}

	MESH_LOCK();
	switch (event->type) {
		case AS_HB_CHANNEL_NODE_CONNECTED:
			// Ignore this event. The subsequent message
			// event will
			// be used for determinine mesh node active
			// status.
			break;
		case AS_HB_CHANNEL_NODE_DISCONNECTED:
			mesh_channel_on_node_disconnect(event);
			break;
		case AS_HB_CHANNEL_MSG_RECEIVED:
			mesh_channel_on_msg_rcvd(event);
			break;
	}

	MESH_UNLOCK();
}

/**
 * Initialize mesh mode data structures.
 */
static void
mesh_init()
{

	if (!IS_MESH()) {
		return;
	}

	MESH_LOCK();

	g_hb.mode_state.mesh_state.status = AS_HB_STATUS_STOPPED;

	// Initialize the mesh node dictionary.
	if (SHASH_OK !=
	    shash_create(&g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			 as_hb_mesh_node_key_hash_fn,
			 sizeof(as_hb_mesh_node_key), sizeof(as_hb_mesh_node),
			 AS_HB_CLUSTER_MAX_SIZE_SOFT, SHASH_CR_MT_BIGLOCK)) {
		CRASH("Error creating mesh node hash.");
	}

	MESH_UNLOCK();
}

/**
 * Delete the shash entries only if they are not seed entries.
 */
static int
mesh_free_node_data_reduce(void* key, void* data, void* udata)
{

	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;

	if (mesh_node->is_seed) {
		mesh_node->status = AS_HB_MESH_NODE_CHANNEL_INACTIVE;
		return SHASH_OK;
	}

	return SHASH_REDUCE_DELETE;
}

/**
 * Remove a host / port from the mesh seed list.
 */
static int
mesh_tip_clear_reduce(void* key, void* data, void* udata)
{

	int rv = SHASH_OK;

	MESH_LOCK();
	cf_node nodeid = ((as_hb_mesh_node_key*)key)->nodeid;
	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;
	as_hb_mesh_tip_clear_udata* tip_clear_udata =
	  (as_hb_mesh_tip_clear_udata*)udata;

	if (mesh_node->is_seed) {
		if (tip_clear_udata->host[0] == '\0') {
			// handling tip clear all
			INFO("Removing mesh seed %s:%d node %" PRIx64,
			     tip_clear_udata->host, tip_clear_udata->port,
			     nodeid);
			rv = SHASH_REDUCE_DELETE;
		} else if (strncmp(mesh_node->mesh_host_name,
				   tip_clear_udata->host, HOST_NAME_MAX) == 0 &&
			   mesh_node->endpoint.port == tip_clear_udata->port) {

			INFO("Removing mesh seed %s:%d node %" PRIx64,
			     tip_clear_udata->host, tip_clear_udata->port,
			     nodeid);

			rv = SHASH_REDUCE_DELETE;
		}
	}
	MESH_UNLOCK();
	if (rv == SHASH_REDUCE_DELETE) {
		if (channel_node_disconnect(nodeid) != 0) {
			WARNING(
			  "Unable to disconnet the channel to node %" PRIx64,
			  nodeid);
		}
	}
	return rv;
}

/**
 * Free the mesh mode data structures.
 */
static void
mesh_clear()
{
	if (!MESH_IS_STOPPED()) {
		WARNING("Attempted clearing mesh module without stopping it. "
			"Skip mesh clear!");
		return;
	}

	MESH_LOCK();
	// Delete the elements from the map.
	shash_reduce_delete(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
			    mesh_free_node_data_reduce, NULL);

	MESH_UNLOCK();
}

/**
 * Open mesh listening socket. Crashes if open failed.
 *
 */
static void
mesh_listening_socket_open(cf_socket** listening_socket)
{

	INFO("Initializing mesh heartbeat socket : %s:%d",
	     config_hb_listen_addr_s_get(), config_hb_listen_port_get());

	MESH_LOCK();

	g_hb.mode_state.mesh_state.socket.addr = config_hb_listen_addr_s_get();
	g_hb.mode_state.mesh_state.socket.port = config_hb_listen_port_get();
	g_hb.mode_state.mesh_state.socket.type = SOCK_STREAM;
	g_hb.mode_state.mesh_state.socket.reuse_addr =
	  (g_config.socket_reuse_addr) ? true : false;

	if (0 != cf_socket_init_server(&g_hb.mode_state.mesh_state.socket)) {
		CRASH("Couldn't initialize unicast heartbeat socket");
	}

	DEBUG("Opened mesh heartbeat socket: %d",
	      CSFD(g_hb.mode_state.mesh_state.socket.sock));

	// Compute the mtu size here and compute the maximum cluster size.
	cf_ip_addr binding_addr;
	cf_ip_addr* binding_addr_p = NULL;
	if (g_hb.mode_state.mesh_state.socket.addr) {
		if (cf_ip_addr_from_string(
		      g_hb.mode_state.mesh_state.socket.addr, &binding_addr) ==
		    0) {
			binding_addr_p = &binding_addr;
		}
	}

	int min_mtu = binding_addr_p && !cf_ip_addr_is_zero(binding_addr_p)
			? cf_inter_mtu(binding_addr_p)
			: cf_inter_min_mtu();

	if (min_mtu == -1) {
		WARNING("Error getting the min MTU. Using the default %d",
			DEFAULT_MIN_MTU);
		min_mtu = DEFAULT_MIN_MTU;
	}
	g_hb.mode_state.mesh_state.min_mtu = min_mtu;
	INFO("MTU of the network is %d.", min_mtu);

	MESH_UNLOCK();

	*listening_socket = g_hb.mode_state.mesh_state.socket.sock;
}

/**
 * Start mesh threads.
 */
static void
mesh_start()
{

	if (!IS_MESH()) {
		return;
	}

	MESH_LOCK();

	cf_socket* listening_socket;
	mesh_listening_socket_open(&listening_socket);
	channel_mesh_listening_sock_register(listening_socket);

	g_hb.mode_state.mesh_state.status = AS_HB_STATUS_RUNNING;

	// Start the mesh tender thread.
	// Start the channel tender.
	if (0 != pthread_create(&g_hb.mode_state.mesh_state.mesh_tender_tid, 0,
				mesh_tender, &g_hb)) {
		CRASH("Could not create channel tender thread: %s",
		      cf_strerror(errno));
	}

	MESH_UNLOCK();
}

/**
 * Reduce function to dump mesh node info to log file.
 */
static int
mesh_dump_reduce(void* key, void* data, void* udata)
{

	as_hb_mesh_node* mesh_node = (as_hb_mesh_node*)data;

	INFO("HB Mesh Node (%s): Node %" PRIx64
	     " Endpoint %s:%d Status %s Last updated %" PRIu64,
	     mesh_node->is_seed ? "seed" : "non-seed", mesh_node->nodeid,
	     IPADDR_TO_STRING(&mesh_node->endpoint.addr),
	     mesh_node->endpoint.port,
	     mesh_node_status_string(mesh_node->status),
	     mesh_node->status == AS_HB_MESH_NODE_CHANNEL_INACTIVE
	       ? mesh_node->last_status_updated
	       : mesh_node->last_status_updated);

	return SHASH_OK;
}

/**
 * Dump mesh state to logs.
 * @param verbose enables / disables verbose logging.
 */
static void
mesh_dump(bool verbose)
{

	if (!IS_MESH()) {
		return;
	}

	cf_info(AS_HB, "HB Mesh RW Retry Timeout:  %d",
		config_hb_mesh_rw_retry_timeout_get());

	if (!verbose) {
		return;
	}

	MESH_LOCK();

	shash_reduce(g_hb.mode_state.mesh_state.nodeid_to_mesh_node,
		     mesh_dump_reduce, NULL);

	MESH_UNLOCK();
}

/*----------------------------------------------------------------------------
 * Multicast submodule.
 *----------------------------------------------------------------------------*/
/**
 * Initialize multicast data structures.
 */
static void
multicast_init()
{
	// No initialization required.
}

/**
 * Clear multicast data structures.
 */
static void
multicast_clear()
{
	// Free multicast data structures. Nothing to do.
}

/**
 * Open multicast socket. Crashes if open failed.

 * @return the socket multicast mode listens on.
 */
static void
multicast_listening_socket_open(cf_socket** listening_socket)
{
	INFO("Initializing multicast heartbeat socket : %s:%d",
	     config_hb_listen_addr_s_get(), config_hb_listen_port_get());

	g_hb.mode_state.multicast_state.socket.conf.addr =
	  config_hb_listen_addr_s_get();
	g_hb.mode_state.multicast_state.socket.conf.port =
	  config_hb_listen_port_get();
	g_hb.mode_state.multicast_state.socket.if_addr =
	  as_hb_ipaddr_is_specified(config_hb_bind_interface_addr_get())
	    ? config_hb_bind_interface_addr_s_get()
	    : NULL;
	g_hb.mode_state.multicast_state.socket.ttl = config_hb_mcast_ttl_get();

	if (0 !=
	    cf_socket_mcast_init(&g_hb.mode_state.multicast_state.socket)) {
		CRASH("couldn't initialize multicast heartbeat socket: %s",
		      cf_strerror(errno));
	}

	DEBUG("Opened multicast socket %d",
	      CSFD(g_hb.mode_state.multicast_state.socket.conf.sock));
	*listening_socket = g_hb.mode_state.multicast_state.socket.conf.sock;

	// Compute the mtu size here and compute the maximum cluster size.
	// Compute the mtu size here and compute the maximum cluster size.
	cf_ip_addr binding_addr;
	cf_ip_addr* binding_addr_p = NULL;
	if (g_hb.mode_state.multicast_state.socket.if_addr) {
		if (cf_ip_addr_from_string(
		      g_hb.mode_state.multicast_state.socket.if_addr,
		      &binding_addr) == 0) {
			binding_addr_p = &binding_addr;
		}
	}

	int min_mtu = binding_addr_p && !cf_ip_addr_is_zero(binding_addr_p)
			? cf_inter_mtu(binding_addr_p)
			: cf_inter_min_mtu();

	if (min_mtu == -1) {
		WARNING("Error getting the min MTU. Using the default %d",
			DEFAULT_MIN_MTU);
		min_mtu = DEFAULT_MIN_MTU;
	}

	g_hb.mode_state.multicast_state.min_mtu = min_mtu;

	INFO("MTU of the network is %d.", min_mtu);
}

/**
 * Start multicast module.
 */
static void
multicast_start()
{
	cf_socket* listening_socket;
	multicast_listening_socket_open(&listening_socket);

	as_hb_endpoint endpoint;
	memset(&endpoint, 0, sizeof(endpoint));
	endpoint.port = config_hb_listen_port_get();
	memcpy(&endpoint.addr, config_hb_listen_addr_get(),
	       sizeof(endpoint.addr));

	channel_multicast_listening_sock_register(listening_socket, &endpoint);
}

/**
 * Close multicast listening socket.
 */
static void
multicast_listening_socket_close()
{
	INFO("closing multicast heartbeat socket : %s:%d",
	     g_hb.mode_state.multicast_state.socket.conf.addr,
	     g_hb.mode_state.multicast_state.socket.conf.port);

	cf_socket_mcast_close(&g_hb.mode_state.multicast_state.socket);

	DEBUG("Closed multicast heartbeat socket");
}

/**
 * Stop Multicast.
 */
static void
multicast_stop()
{
	channel_multicast_listening_sock_deregister(
	  g_hb.mode_state.multicast_state.socket.conf.sock);

	multicast_listening_socket_close();
}

/**
 * Dump multicast state to logs.
 * @param verbose enables / disables verbose logging.
 */
static void
multicast_dump(bool verbose)
{

	if (!IS_MESH()) {
		// Mode is multicast.
		INFO("HB MCast TTL:  %d", config_hb_mcast_ttl_get());
	}
}

/**
 * Find the maximum cluster size based on MTU of the network.
 *
 * num_nodes is computed so that
 *
 * MTU = compression_factor * (fixed_size +  num_nodes * per_node_size)
 * where,
 * fixed_size = udp_header_size + msg_header_size + sigma(per_plugin_fixed_size)
 * per_node_size = sigma(per_plugin_per_node_size).
 */
static int
multicast_supported_cluster_size_get()
{
	// Derive the size based on the underlying network mtu.
	return msg_supported_nodes_get(MTU());
}

/*----------------------------------------------------------------------------
 * Heartbeat main submodule.
 *----------------------------------------------------------------------------*/
/**
 * Initialize the mode specific data structures.
 */
static void
hb_mode_init()
{
	if (IS_MESH()) {
		mesh_init();
	} else {
		multicast_init();
	}
}

/**
 * Start mode specific threads..
 */
static void
hb_mode_start()
{
	if (IS_MESH()) {
		mesh_start();
	} else {
		multicast_start();
	}
}

/**
 * Initialize the template to be used for heartbeat messages.
 */
static void
hb_msg_init()
{
	// Register fabric heartbeat msg type with no processing
	// function:
	// This permits getting / putting heartbeat msgs to be moderated
	// via an idle msg queue.
	as_fabric_register_msg_fn(M_TYPE_HEARTBEAT, g_hb_msg_template,
				  sizeof(g_hb_msg_template),
				  AS_HB_MSG_SCRATCH_SIZE, 0, 0);

	// Register old heartbeat msg type. For compatibility with other
	// nodes
	as_fabric_register_msg_fn(M_TYPE_HEARTBEAT_V2, g_hb_v2_msg_template,
				  sizeof(g_hb_v2_msg_template),
				  AS_HB_V2_MSG_SCRATCH_SIZE, 0, 0);
}

/**
 * Publish an event to subsystems listening to heart beat events.
 */
static void
hb_event_queue(as_hb_event_type event_type, cf_node* nodes, int node_count)
{
	// Lockless because the queue is thread safe and we do not use
	// heartbeat
	// state here.
	for (int i = 0; i < node_count; i++) {
		as_hb_event_node event;
		event.evt = event_type;
		event.nodeid = nodes[i];

		event.event_detected_time = cf_getms();
		if (event_type == AS_HB_NODE_DEPART) {
			event.event_time =
			  NODE_DEPART_TIME(event.event_detected_time);
		} else {
			event.event_time = event.event_detected_time;
		}

		DEBUG("Queuing event of type %d for node %" PRIx64, event.evt,
		      event.nodeid);
		if (cf_queue_push(&g_hb_event_listeners.external_events_queue,
				  &event) != 0) {
			CRASH("Error queuing up external heartbeat "
			      "event for "
			      "node %" PRIx64,
			      nodes[i]);
		}
	}
}

/**
 * Publish all pending events.
 */
static void
hb_event_publish_pending()
{
	cf_clock now = cf_getms();
	cf_clock last_published;
	HB_LOCK();
	last_published = g_hb_event_listeners.external_events_published_last;
	HB_UNLOCK();

	int num_events =
	  cf_queue_sz(&g_hb_event_listeners.external_events_queue);
	if (last_published + AS_HB_EVENT_PUBLISH_INTERVAL() > now ||
	    num_events <= 0) {
		// Events need not be published.
		return;
	}

	as_hb_event_node events[AS_HB_CLUSTER_MAX_SIZE_SOFT];
	int published_count = 0;
	while (cf_queue_pop(&g_hb_event_listeners.external_events_queue,
			    &events[published_count], 0) == CF_QUEUE_OK &&
	       published_count <= AS_HB_CLUSTER_MAX_SIZE_SOFT) {
		published_count++;
	}

	if (published_count) {
		// Assuming that event listeners are not registerd after
		// system
		// init, no locks here.
		DEBUG("Publishing heartbeat %d events", published_count);
		for (int i = 0; i < g_hb_event_listeners.event_listener_count;
		     i++) {
			(g_hb_event_listeners.event_listeners[i]
			   .event_callback)(
			  published_count, events,
			  g_hb_event_listeners.event_listeners[i].udata);
		}
	}

	HB_LOCK();
	// update last published.
	g_hb_event_listeners.external_events_published_last = now;
	HB_UNLOCK();
};

/**
 * Delete the plugin data while itereating through the map.
 */
static int
hb_adjacency_free_plugin_data_reduce(void* key, void* data, void* udata)
{

	as_hb_adjacent_node* adjacent_node = (as_hb_adjacent_node*)data;

	cf_node* nodeid = (cf_node*)key;

	hb_adjacent_node_destroy(adjacent_node);

	// Send event depart to for this node
	hb_event_queue(AS_HB_NODE_DEPART, nodeid, 1);

	return SHASH_REDUCE_DELETE;
}

/**
 * Clear the heartbeat datastructures.
 */
static void
hb_clear()
{

	if (!HB_IS_STOPPED()) {
		WARNING(
		  "Attempted to clear heartbeat module without stopping it.");
		return;
	}

	HB_LOCK();

	// Free the plugin data and delete adjacent nodes.
	shash_reduce_delete(g_hb.adjacency,
			    hb_adjacency_free_plugin_data_reduce, NULL);

	HB_UNLOCK();

	// Publish node departed events for the removed nodes.
	hb_event_publish_pending();

	// Clear the mode module.
	if (IS_MESH()) {
		mesh_clear();
	} else {
		multicast_clear();
	}

	channel_clear();
}

/**
 * Reduce function to get hold of current adjacency list.
 */
static int
hb_adjacency_iterate_reduce(void* key, void* data, void* udata)
{

	cf_node* nodeid = (cf_node*)key;
	as_hb_adjacency_reduce_udata* adjacency_reduce_udata =
	  (as_hb_adjacency_reduce_udata*)udata;

	adjacency_reduce_udata->adj_list[adjacency_reduce_udata->adj_count] =
	  *nodeid;
	adjacency_reduce_udata->adj_count++;

	return SHASH_OK;
}

/**
 * Plugin function to set heartbeat adjacency list into a pluse message.
 */
static void
hb_plugin_set_fn(msg* msg)
{

	if (!HB_IS_MSG_LEGACY(msg)) {

		HB_LOCK();

		cf_node adj_list[shash_get_size(g_hb.adjacency)];
		as_hb_adjacency_reduce_udata adjacency_reduce_udata = {
			adj_list, 0
		};

		shash_reduce(g_hb.adjacency, hb_adjacency_iterate_reduce,
			     &adjacency_reduce_udata);

		HB_UNLOCK();

		// Populate adjacency list.
		msg_adjacency_set(msg, adj_list,
				  adjacency_reduce_udata.adj_count);

		// Set cluster id
		char cluster_id[AS_CLUSTER_ID_SZ];
		as_config_cluster_id_get(cluster_id);
		if (cluster_id[0] != 0 &&
		    msg_set_str(msg, AS_HB_MSG_CLUSTER_ID, cluster_id,
				MSG_SET_COPY) != 0) {
			CRASH("Error setting cluster id on msg.");
		}

	} else {
		// In v1 and v2 succession list passes around which will
		// be
		// taken care by the paxos plugin. Adjacency list is not
		// sent
		// with the message.
	}
}

/**
 * Plugin function that parses adjacency list out of a heartbeat pulse
 * message.
 */
static void
hb_plugin_parse_data_fn(msg* msg, cf_node source,
			as_hb_plugin_node_data* plugin_data)
{
	size_t adj_length = 0;
	cf_node* adj_list = NULL;

	if (msg_adjacency_get(msg, &adj_list, &adj_length) != 0) {
		// store a zero length adjacency list. Should not have
		// happened.
		WARNING("Received heartbeat without adjacency list %" PRIx64,
			source);
		adj_length = 0;
	}

	// Skip the source node in the adjacency list, which will be there for
	// older heart beat versions.
	int final_list_length = 0;
	for (int i = 0; i < adj_length; i++) {
		if (adj_list[i] == source) {
			continue;
		}
		final_list_length++;
	}

	int data_size = sizeof(size_t) + (final_list_length * sizeof(cf_node));

	if (data_size > plugin_data->data_capacity) {

		// Round up to nearest multiple of block size to prevent very
		// frequent reallocation.
		size_t data_capacity =
		  ((data_size + HB_PLUGIN_DATA_BLOCK_SIZE - 1) /
		   HB_PLUGIN_DATA_BLOCK_SIZE) *
		  HB_PLUGIN_DATA_BLOCK_SIZE;

		// Reallocate since we have outgrown existing capacity.
		plugin_data->data =
		  cf_realloc(plugin_data->data, data_capacity);

		if (plugin_data->data == NULL) {
			CRASH("Error allocating space for storing adjacency "
			      "list for "
			      "node %" PRIx64,
			      source);
		}
		plugin_data->data_capacity = data_capacity;
	}
	plugin_data->data_size = data_size;

	memcpy(plugin_data->data, &final_list_length, sizeof(size_t));
	cf_node* dest_list = (cf_node*)(plugin_data->data + sizeof(size_t));

	int dest_index = 0;
	for (int i = 0; i < adj_length; i++) {
		if (adj_list[i] == source) {
			continue;
		}

		dest_list[dest_index++] = adj_list[i];
	}
}

/**
 * Get the msg buffer from a pool based on the protocol under use.
 * @return the msg buff
 */
static msg*
hb_msg_get()
{
	return as_fabric_msg_get(HB_IS_PROTOCOL_LEGACY() ? M_TYPE_HEARTBEAT_V2
							 : M_TYPE_HEARTBEAT);
}

/**
 * Return the message buffer back to the pool.
 */
static void
hb_msg_return(msg* msg)
{
	as_fabric_msg_put(msg);
}

/**
 * Fill the outgoing pulse message with plugin specific data.
 *
 * Note: The set functions would be acquiring their locks. This function
 * should
 * never directly use nor have a call stack under HB_LOCK.
 *
 * @param msg the outgoing pulse message.
 */
static void
hb_plugin_msg_fill(msg* msg)
{

	for (int i = 0; i < AS_HB_PLUGIN_SENTINEL; i++) {
		if (g_hb.plugins[i].set_fn) {
			(g_hb.plugins[i].set_fn)(msg);
		}
	}
}

/**
 * Parse fields from the message into plugin specific data.
 * @param msg the outgoing pulse message.
 * @param adjacent_node the node from which this message was received.
 * @param plugin_data_changed (output) array whose ith entry is set to true if
 * ith plugin's data changed, false otherwise. Should be large enough to hold
 * flags for all plugins.
 */
static void
hb_plugin_msg_parse(msg* msg, as_hb_adjacent_node* adjacent_node,
		    as_hb_plugin* plugins, bool plugin_data_changed[])
{

	cf_node source;
	adjacent_node->plugin_data_cycler++;

	msg_nodeid_get(msg, &source);
	for (int i = 0; i < AS_HB_PLUGIN_SENTINEL; i++) {
		plugin_data_changed[i] = false;
		if (g_hb.plugins[i].parse_fn) {

			as_hb_plugin_node_data* curr_data =
			  &adjacent_node->plugin_data
			     [i][adjacent_node->plugin_data_cycler % 2];

			as_hb_plugin_node_data* prev_data =
			  &adjacent_node->plugin_data
			     [i][(adjacent_node->plugin_data_cycler + 1) % 2];

			// Ensure there is a preallocated data pointer.
			if (curr_data->data == NULL) {
				curr_data->data =
				  cf_malloc(AS_HB_PLUGIN_DATA_DEFAULT_SIZE);
				if (curr_data->data == NULL) {
					CRASH("Error allocating plugin data.");
				}
			}

			// Parse message data into current data.
			(g_hb.plugins[i]).parse_fn(msg, source, curr_data);

			if (!plugins[i].change_listener) {
				// No change listener configured. Skip detecting
				// change.
				continue;
			}

			size_t curr_data_size = curr_data->data_size;
			void* curr_data_blob =
			  curr_data_size ? curr_data->data : NULL;

			size_t prev_data_size = prev_data->data_size;
			void* prev_data_blob =
			  prev_data_size ? prev_data->data : NULL;

			if (prev_data_blob == curr_data_blob) {
				// Old and new data both NULL or both point to
				// the same memory location.
				plugin_data_changed[i] = false;
				continue;
			}

			if (prev_data_size != curr_data_size ||
			    prev_data_blob == NULL || curr_data_blob == NULL) {
				// Plugin data definitely changed, as the data
				// sizes differ or exactly one of old or new
				// data pointers is NULL.
				plugin_data_changed[i] = true;
				continue;
			}

			// The data sizes match at this point and neither values
			// are NULL.
			plugin_data_changed[i] =
			  memcmp(prev_data_blob, curr_data_blob,
				 curr_data_size) != 0;
		}
	}
}

/**
 * Initialize the plugin specific data structures.
 */
static void
hb_plugin_init()
{
	memset(&g_hb.plugins, 0, sizeof(g_hb.plugins));

	// Be cute. Register self as a plugin.
	as_hb_plugin self_plugin;
	memset(&self_plugin, 0, sizeof(self_plugin));
	self_plugin.id = AS_HB_PLUGIN_HB;
	self_plugin.wire_size_fixed = 0;
	self_plugin.wire_size_per_node = sizeof(cf_node);
	self_plugin.set_fn = hb_plugin_set_fn;
	self_plugin.parse_fn = hb_plugin_parse_data_fn;
	hb_plugin_register(&self_plugin);
}

/**
 * Transmits heartbeats at fixed intervals.
 */
static void*
hb_transmitter(void* arg)
{
	DETAIL("Heartbeat transmitter started.");
	while (HB_IS_RUNNING()) {

		// Construct the pulse message.
		msg* msg = hb_msg_get();

		msg_src_fields_fill(msg);
		msg_type_set(msg, AS_HB_MSG_TYPE_PULSE);

		// Have plugins fill their data into the heartbeat
		// pulse message.
		hb_plugin_msg_fill(msg);

		// Broadcast the heartbeat to all known recepients.
		channel_msg_broadcast(msg);

		// Return the msg back to the fabric.
		hb_msg_return(msg);

		DETAIL("Done sending pulse message.");
		usleep(PULSE_TRANSMIT_INTERVAL() * 1000);
	}

	DETAIL("Heartbeat transmitter stopped.");
	return NULL;
}

/**
 * Get hold of adjacent node information given its nodeid.
 * @param nodeid the nodeid.
 * @param adjacent_node the output node information.
 * @return 0 on success, -1 on failure.
 */
static int
hb_adjacent_node_get(cf_node nodeid, as_hb_adjacent_node* adjacent_node)
{
	int rv = -1;
	HB_LOCK();

	if (SHASH_GET_OR_DIE(
	      g_hb.adjacency, &nodeid, adjacent_node,
	      "Error reading adjacecny information for node %" PRIx64,
	      nodeid) == SHASH_OK) {
		rv = 0;
	}

	HB_UNLOCK();
	return rv;
}

/**
 * Inidicates if a give node has expired and should be removed from the
 * adjacency list.
 */
static bool
hb_node_has_expired(cf_node nodeid, as_hb_adjacent_node* adjacent_node)
{
	bool expired = false;

	if (nodeid == config_self_nodeid_get()) {
		return false;
	}

	HB_LOCK();

	cf_clock now = cf_getms();

	bool adjacency_expired =
	  adjacent_node->lasted_updated_monotonic_ts + AS_HB_NODE_TIMEOUT() <
	  now;

	uint64_t fabric_lasttime;

	bool fabric_expired = true;
	if (as_fabric_get_node_lasttime(nodeid, &fabric_lasttime) == 0) {
		fabric_expired = fabric_lasttime > AS_HB_NODE_TIMEOUT();
	}

	// Judge the expiry of this node based on fabric and adjacency
	// status.
	if (!fabric_expired && !adjacency_expired) {
		// Fabric and heartbeat messages going on fine.
		expired = false;
	} else if (!fabric_expired && adjacency_expired) {
		// Use a grace period because fabric messages are being
		// received.
		expired = adjacent_node->lasted_updated_monotonic_ts +
			    AS_HB_FABRIC_GRACE_PERIOD() <
			  now;
	} else if (fabric_expired && !adjacency_expired) {
		// Maybe fabric is quiet because there is no fabric
		// communication required.
		expired = false;
	} else {
		expired = true;
	}

	// Update error stats
	if (adjacency_expired) {
		stats_error_count(AS_HB_ERR_EXPIRE_HB);
		stats_error_count(fabric_expired ? AS_HB_ERR_EXPIRE_FAB_DEAD
						 : AS_HB_ERR_EXPIRE_FAB_ALIVE);
	}

	DETAIL("For node %" PRIx64
	       " hb expired:%s fabric expired:%s deemed expired: %s",
	       nodeid, adjacency_expired ? "true" : "false",
	       fabric_expired ? "true" : "false", expired ? "true" : "false");

	HB_UNLOCK();
	return expired;
}

/**
 * Free up space occupied by plugin data from adjacent node.
 */
static void
hb_adjacent_node_destroy(as_hb_adjacent_node* adjacent_node)
{
	HB_LOCK();
	for (int i = 0; i < AS_HB_PLUGIN_SENTINEL; i++) {
		for (int j = 0; j < 2; j++) {

			if (adjacent_node->plugin_data[i][j].data) {
				cf_free(adjacent_node->plugin_data[i][j].data);
				adjacent_node->plugin_data[i][j].data = NULL;
			}

			adjacent_node->plugin_data[i][j].data_capacity = 0;
			adjacent_node->plugin_data[i][j].data_size = 0;
		}
	}

	HB_UNLOCK();
}

/**
 * Tend reduce function that removes expired nodes from adjacency list.
 */
static int
hb_adjacency_tend_reduce(void* key, void* data, void* udata)
{

	cf_node nodeid = *(cf_node*)key;
	as_hb_adjacent_node* adjacent_node = (as_hb_adjacent_node*)data;
	as_hb_adjacency_tender_udata* adjacency_tender_udata =
	  (as_hb_adjacency_tender_udata*)udata;

	int rv = SHASH_OK;
	if (hb_node_has_expired(nodeid, adjacent_node)) {
		DEBUG("Node expired %" PRIx64, nodeid);
		adjacency_tender_udata
		  ->dead_node_list[adjacency_tender_udata->dead_node_count++] =
		  nodeid;

		// Free plugin data as well.
		hb_adjacent_node_destroy(adjacent_node);

		rv = SHASH_REDUCE_DELETE;
	}

	return rv;
}

/**
 * Tends the adjacency list. Removes nodes that expire.
 */
static void*
hb_adjacency_tender(void* arg)
{

	DETAIL("Adjacency tender started.");
	while (HB_IS_RUNNING()) {

		DETAIL("Tending adjacency list.");
		HB_LOCK();
		cf_node dead_nodes[shash_get_size(g_hb.adjacency)];
		as_hb_adjacency_tender_udata adjacency_tender_udata;
		adjacency_tender_udata.dead_node_list = dead_nodes;
		adjacency_tender_udata.dead_node_count = 0;

		shash_reduce_delete(g_hb.adjacency, hb_adjacency_tend_reduce,
				    &adjacency_tender_udata);

		HB_UNLOCK();

		if (adjacency_tender_udata.dead_node_count > 0) {
			// Queue events for dead nodes.
			hb_event_queue(AS_HB_NODE_DEPART, dead_nodes,
				       adjacency_tender_udata.dead_node_count);
		}

		// See if we have pending events to publish.
		hb_event_publish_pending();

		DETAIL("Done tending adjacency list.");

		// Sleep for some time.
		// TODO: Is this too fast?
		usleep(ADJACENCY_TEND_INTERVAL() * 1000);
	}

	DETAIL("Adjacency tender shut down.");
	return NULL;
}

/**
 * Start the transmitter thread.
 */
static void
hb_tx_start()
{
	// Start the transmitter thread.
	if (0 !=
	    pthread_create(&g_hb.transmitter_tid, 0, hb_transmitter, &g_hb)) {
		CRASH("could not create heartbeat transmitter thread: %s",
		      cf_strerror(errno));
	}
}

/**
 * Stop the transmitter thread.
 */
static void
hb_tx_stop()
{
	DETAIL("Waiting for the transmitter thread to stop.");
	// Wait for the adjacency tender thread to stop.
	pthread_join(g_hb.transmitter_tid, NULL);
}

/**
 * Start the transmitter thread.
 */
static void
hb_adjacency_tender_start()
{
	// Start the transmitter thread.
	if (0 != pthread_create(&g_hb.adjacency_tender_tid, 0,
				hb_adjacency_tender, &g_hb)) {
		CRASH("Could not create heartbeat adjacency tender "
		      "thread: %s",
		      cf_strerror(errno));
	}
}

/**
 * Stop the adjacency tender thread.
 */
static void
hb_adjacency_tender_stop()
{
	// Wait for the adjacency tender thread to stop.
	pthread_join(g_hb.adjacency_tender_tid, NULL);
}

/**
 * Initialize the heartbeat subsystem.
 */
static void
hb_init()
{

	if (HB_IS_INITIALIZED()) {
		WARNING("Heartbeat main module is already initialized.");
		return;
	}

	// Operate under a lock. Let's be paranoid everywhere.
	HB_LOCK();

	// Initialize the heartbeat datastructure
	memset(&g_hb, 0, sizeof(g_hb));

	// Initialize the adjacencies
	if (SHASH_OK !=
	    shash_create(&g_hb.adjacency, cf_nodeid_shash_fn, sizeof(cf_node),
			 sizeof(as_hb_adjacent_node),
			 AS_HB_CLUSTER_MAX_SIZE_SOFT, SHASH_CR_MT_BIGLOCK)) {
		CRASH("Error creating adjacencies hash.");
	}

	// Initialize unpublished event queue.
	if (!cf_queue_init(&g_hb_event_listeners.external_events_queue,
			   sizeof(as_hb_event_node),
			   AS_HB_CLUSTER_MAX_SIZE_SOFT, true)) {
		CRASH("Error creating heartbeat event queue.");
	}

	g_hb_event_listeners.external_events_published_last = 0;

	// Initialize the mode specific state
	hb_mode_init();

	// Initialize the plugin functions
	hb_plugin_init();

	// Initialize IO channel subsysem
	channel_init();

	g_hb.status = AS_HB_STATUS_STOPPED;

	HB_UNLOCK();
}

/**
 * Start the heartbeat subsystem.
 */
static void
hb_start()
{

	// Operate under a lock. Let's be paranoid everywhere.
	HB_LOCK();

	if (HB_IS_RUNNING()) {
		// shutdown the heartbeat subsystem.
		hb_stop();
	}

	g_hb.status = AS_HB_STATUS_RUNNING;

	// Initialize the heartbeat message templates. Called from here
	// because
	// fabric needs to be initialized for this call to succeed.
	// Fabric init
	// happens after heartbeat init.
	hb_msg_init();

	// Initialize channel submodule.
	channel_start();

	// Start the mode submodule
	hb_mode_start();

	// Start heart beat transmitter.
	hb_tx_start();

	// Start heart beat adjacency tender.
	hb_adjacency_tender_start();

	HB_UNLOCK();
}

/**
 * Register a plugin with the heart beat system.
 */
static void
hb_plugin_register(as_hb_plugin* plugin)
{
	HB_LOCK();
	memcpy(&g_hb.plugins[plugin->id], plugin, sizeof(as_hb_plugin));
	HB_UNLOCK();
}

/**
 * Shut down the heartbeat subsystem.
 */
static void
hb_stop()
{
	if (!HB_IS_RUNNING()) {
		WARNING("Heartbeat is already stopped.");
		return;
	}

	HB_LOCK();
	g_hb.status = AS_HB_STATUS_SHUTTING_DOWN;
	HB_UNLOCK();

	// Publish pending events. Should not delay any events.
	hb_event_publish_pending();

	// Shutdown mode.
	if (IS_MESH()) {
		mesh_stop();
	} else {
		multicast_stop();
	}

	// Wait for the threads to shut down.
	hb_tx_stop();

	hb_adjacency_tender_stop();

	// Stop channels.
	channel_stop();

	g_hb.status = AS_HB_STATUS_STOPPED;
}

/**
 * Process an incoming pulse message.
 */
static void
hb_channel_on_pulse(as_hb_channel_event* msg_event)
{

	msg* msg = msg_event->msg;
	cf_node source;

	// Print cluster breach only once per second.
	static cf_clock last_cluster_breach_print = 0;

	// Channel has validated the source. Don't bother checking here.
	msg_nodeid_get(msg, &source);

	if (source == config_self_nodeid_get()) {
		// Ingore self heatbeats.
		cf_atomic_int_incr(&g_stats.heartbeat_received_self);
		return;
	}

	// Ingore self heatbeats.
	cf_atomic_int_incr(&g_stats.heartbeat_received_foreign);

	// If this node encounters other nodes at startup, prevent it
	// from switching to a single-node cluster.
	as_partition_balance_init_multi_node_cluster();

	HB_LOCK();

	as_hb_adjacent_node adjacent_node;
	memset(&adjacent_node, 0, sizeof(adjacent_node));

	bool plugin_data_changed[AS_HB_PLUGIN_SENTINEL] = { 0 };
	bool is_new = hb_adjacent_node_get(source, &adjacent_node) != 0;

	if (!is_new) {

		if (as_hlc_timestamp_order_get(
		      msg_event->msg_hlc_ts.send_ts,
		      adjacent_node.last_msg_hlc_ts.send_ts) ==
		    AS_HLC_HAPPENS_BEFORE) {
			// Received a delayed heartbeat send before the current
			// heartbeat.
			WARNING("Ignoring delayed heartbeat. Expected "
				"timestamp less than %" PRIu64
				" but was  %" PRIu64 " from "
				"node: %" PRIx64,
				adjacent_node.last_msg_hlc_ts.send_ts,
				msg_event->msg_hlc_ts.send_ts, source);
			goto Exit;
		}
	}

	// Update all fields irrespective of whether this is a new node
	msg_id_get(msg, &adjacent_node.hb_protocol_version);

	// Get the ip address.
	as_hb_endpoint endpoint;
	memset(&endpoint, 0, sizeof(endpoint));
	msg_endpoint_get(msg, &endpoint);

	adjacent_node.addr = endpoint.addr;

	// Populate plugin data.
	hb_plugin_msg_parse(msg, &adjacent_node, g_hb.plugins,
			    plugin_data_changed);

	// Update the last updated time.
	adjacent_node.lasted_updated_monotonic_ts = cf_getms();
	memcpy(&adjacent_node.last_msg_hlc_ts, &msg_event->msg_hlc_ts,
	       sizeof(as_hlc_msg_timestamp));

	int mcsize = config_mcsize();

	// Note: adjacency list does not contain self node hence
	// (mcsize - 1) in the check.
	if (is_new && shash_get_size(g_hb.adjacency) >= (mcsize - 1)) {
		if (last_cluster_breach_print != (cf_getms() / 1000L)) {
			WARNING("Exceeding maximum supported cluster size %d. "
				"Ignoring "
				"node: %" PRIx64,
				mcsize, source);
			last_cluster_breach_print = cf_getms() / 1000L;
		}
		goto Exit;
	}

	// Update plugin data, update times, etc.
	SHASH_PUT_OR_DIE(g_hb.adjacency, &source, &adjacent_node,
			 "Error allocating space for adjacent node %" PRIx64,
			 source);

	// Publish event if this is a new node.
	if (is_new) {
		DEBUG("Node arrived %" PRIx64, source);
		hb_event_queue(AS_HB_NODE_ARRIVE, &source, 1);
	}

Exit:
	HB_UNLOCK();

	// Call plugin change listeners outside of a lock to prevent deadlocks.
	for (int i = 0; i < AS_HB_PLUGIN_SENTINEL; i++) {
		if (plugin_data_changed[i] && g_hb.plugins[i].change_listener) {
			// Notify that data for this plugin for the source node
			// has changed.
			DETAIL("Plugin data for node %" PRIx64
			       " changed for plugin %d",
			       source, i);
			(g_hb.plugins[i]).change_listener(source);
		}
	}
}

/**
 * Process an incoming heartbeat message.
 */
static void
hb_channel_on_msg_rcvd(as_hb_channel_event* event)
{
	msg* msg = event->msg;
	as_hb_msg_type type;
	msg_type_get(msg, &type);

	switch (type) {
		case AS_HB_MSG_TYPE_PULSE:
			// A pulse message. Update the adjacent node data.
			hb_channel_on_pulse(event);
			break;
		default:
			// Ignore other messages.
			break;
	}
}

/**
 * Process channel events.
 */
static void
hb_channel_event_process(as_hb_channel_event* event)
{
	// Deal with pulse messages here.
	switch (event->type) {
		case AS_HB_CHANNEL_MSG_RECEIVED:
			hb_channel_on_msg_rcvd(event);
			break;
		default:
			// Ignore channel active and inactive events.
			// Rather
			// rely on the adjacency tender to expire nodes.
			break;
	}
}

/**
 * Dump hb mode state to logs.
 * @param verbose enables / disables verbose logging.
 */
static void
hb_mode_dump(bool verbose)
{
	if (IS_MESH()) {
		mesh_dump(verbose);
	} else {
		multicast_dump(verbose);
	}
}

/**
 * Reduce function to dump hb node info to log file.
 */
static int
hb_dump_reduce(void* key, void* data, void* udata)
{

	cf_node* nodeid = (cf_node*)key;
	as_hb_adjacent_node* adjacent_node = (as_hb_adjacent_node*)data;

	INFO("HB Adjacent Node: Node %" PRIx64 " Protocol %" PRIu32
	     " IP Address %s Last Updated %" PRIu64,
	     *nodeid, adjacent_node->hb_protocol_version,
	     IPADDR_TO_STRING(&adjacent_node->addr),
	     adjacent_node->lasted_updated_monotonic_ts);

	return SHASH_OK;
}

/**
 * Dump hb state to logs.
 * @param verbose enables / disables verbose logging.
 */
static void
hb_dump(bool verbose)
{

	HB_LOCK();

	INFO("HB Adjacency Size: %d", shash_get_size(g_hb.adjacency));

	if (verbose) {
		// Nothing to dump in non-verbose mode.
		shash_reduce(g_hb.adjacency, hb_dump_reduce, NULL);
	}

	HB_UNLOCK();
}

/**
 * Compute a complement / inverted adjacency graph for input nodes such that
 * entry
 *
 *      inverted_graph[i][j] = 0 iff node[i] and node[j] are in each
 *  other's adjacency lists. That is they have a bidirectional network
 *  link active between them.
 *
 *  else
 *
 *      inverted_graph[i][j] > 0 iff there is no link or a unidirectional link
 * between them.
 *
 *
 * @param nodes the input vector of nodes.
 * @param inverted_graph (output) a (num_nodes x num_nodes ) 2D byte array.
 */
static void
hb_adjacency_graph_invert(cf_vector* nodes, uint8_t** inverted_graph)
{
	int num_nodes = cf_vector_size(nodes);

	for (int i = 0; i < num_nodes; i++) {
		for (int j = 0; j < num_nodes; j++) {
			inverted_graph[i][j] = 2;
		}
	}

	cf_node self_nodeid = config_self_nodeid_get();
	int self_node_index = vector_find(nodes, &self_nodeid);

	HB_LOCK();
	for (int i = 0; i < num_nodes; i++) {
		// Mark the node connected from itself, i.e, disconnected in the
		// inverted graph.
		inverted_graph[i][i] = 0;

		cf_node node = *(cf_node*)cf_vector_getp(nodes, i);
		as_hb_adjacent_node node_info;

		if (!hb_adjacent_node_get(node, &node_info)) {

			if (self_node_index >= 0) {
				// Self node will not have plugin data. But the
				// fact that this node has an adjacent node
				// indicates that is is in our adjacency list.
				// Adjust the graph.
				inverted_graph[i][self_node_index]--;
				inverted_graph[self_node_index][i]--;
			}

			cf_node* adjacency_list =
			  (cf_node*)node_info.plugin_data
			    [AS_HB_PLUGIN_HB][node_info.plugin_data_cycler % 2]
			      .data;
			int adjacency_length =
			  node_info.plugin_data
			    [AS_HB_PLUGIN_HB][node_info.plugin_data_cycler % 2]
			      .data_size /
			  sizeof(cf_node);

			for (int j = 0; j < adjacency_length; j++) {
				cf_node other_node = adjacency_list[j];
				int other_node_index =
				  vector_find(nodes, &other_node);
				if (other_node_index < 0) {
					// This node is not in the input set of
					// nodes.
					continue;
				}

				if (i != other_node_index) {
					inverted_graph[i][other_node_index]--;
					inverted_graph[other_node_index][i]--;
				}
			}
		}
	}

	HB_UNLOCK();
}

/**
 * Compute the nodes to evict from the input nodes so that remaining nodes form
 * a clique, based on
 * adjacency lists.
 * @param nodes input cf_node vector.
 * @param nodes_to_evict output cf_node clique array, that is initialized.
 */
static void
hb_maximal_clique_evict(cf_vector* nodes, cf_vector* nodes_to_evict)
{

	int num_nodes = cf_vector_size(nodes);

	if (num_nodes == 0) {
		// Nothing to do.
		return;
	}

	int graph_alloc_size = sizeof(uint8_t) * num_nodes * num_nodes;
	void* graph_data = MSG_BUFF_ALLOC(graph_alloc_size);

	if (!graph_data) {
		// Kick the can down the road.
		WARNING(
		  "Error allocating space for clique finding data structure.");
		return;
	}

	uint8_t* inverted_graph[num_nodes];
	inverted_graph[0] = graph_data;
	for (int i = 1; i < num_nodes; i++) {
		inverted_graph[i] = *inverted_graph + num_nodes * i;
	}

	hb_adjacency_graph_invert(nodes, inverted_graph);

	// Count the number of edges in the inverted graph. These edges are the
	// ones that need to be removed so that the remaining nodes forn a
	// clique in the adjacency graph.
	int edge_count = 0;
	for (int i = 0; i < num_nodes; i++) {
		for (int j = 0; j < num_nodes; j++) {
			if (inverted_graph[i][j]) {
				edge_count++;
			}
		}
	}

	// The minimal vertex cover on this graph is the set of nodes that
	// should be removed to result in  a clique on the remaining nodes.
	// This implementation is an approximation of the minimal vertex cover.
	// The notion is to keep removing vertices having the highest degree
	// until there are no more edges remaining. The heuristic gets rid of
	// the more
	// problematic nodes first.

	cf_vector_delete_range(nodes_to_evict, 0,
			       cf_vector_size(nodes_to_evict) - 1);

	while (edge_count > 0) {
		// Find vertex with highest degree.
		cf_node max_degree_node = 0;
		int max_degree_node_idx = -1;
		int max_degree = 0;

		for (int i = 0; i < num_nodes; i++) {
			cf_node to_evict = 0;
			cf_vector_get(nodes, i, &to_evict);

			if (vector_find(nodes_to_evict, &to_evict) >= 0) {
				// We have already decided to evict this node.
				continue;
			}

			if (to_evict == config_self_nodeid_get()) {
				// Do not evict self.
				continue;
			}

			// Get the degree of this node.
			int degree = 0;
			for (int j = 0; j < num_nodes; j++) {
				if (inverted_graph[i][j]) {
					degree++;
				}
			}

			DETAIL("Inverted degree for node %" PRIx64 " is %d",
			       to_evict, degree);

			// See if this node has a higher degree. On ties choose
			// the node with a smaller nodeid
			if (degree > max_degree ||
			    (degree == max_degree &&
			     max_degree_node > to_evict)) {
				max_degree = degree;
				max_degree_node = to_evict;
				max_degree_node_idx = i;
			}
		}

		if (max_degree_node_idx < 0) {
			// We are done no node to evict.
			break;
		}

		DEBUG("Marking node %" PRIx64
		      " with degree %d for clique based eviction.",
		      max_degree_node, max_degree);

		cf_vector_append(nodes_to_evict, &max_degree_node);

		// Remove all edges attached to the removed node.
		for (int i = 0; i < num_nodes; i++) {
			if (inverted_graph[max_degree_node_idx][i]) {
				inverted_graph[max_degree_node_idx][i] = 0;
				edge_count--;
			}
			if (inverted_graph[i][max_degree_node_idx]) {
				inverted_graph[i][max_degree_node_idx] = 0;
				edge_count--;
			}
		}
	}

	MSG_BUFF_FREE(graph_data, graph_alloc_size);
}

/**
 * Reduce function to iterate over plugin data for all adjacecnt nodes.
 */
static int
hb_plugin_data_iterate_reduce(void* key, void* data, void* udata)
{
	cf_node* nodeid = (cf_node*)key;
	as_hb_adjacent_node* adjacent_node = (as_hb_adjacent_node*)data;
	as_hb_adjacecny_iterate_reduce_udata* reduce_udata =
	  (as_hb_adjacecny_iterate_reduce_udata*)udata;

	size_t plugin_data_size =
	  adjacent_node->plugin_data[reduce_udata->pluginid]
				    [adjacent_node->plugin_data_cycler % 2]
				      .data_size;
	void* plugin_data =
	  plugin_data_size
	    ? adjacent_node->plugin_data[reduce_udata->pluginid]
					[adjacent_node->plugin_data_cycler % 2]
					  .data
	    : NULL;

	reduce_udata->iterate_fn(*nodeid, plugin_data, plugin_data_size,
				 adjacent_node->lasted_updated_monotonic_ts,
				 &adjacent_node->last_msg_hlc_ts,
				 reduce_udata->udata);

	return SHASH_OK;
}

/**
 * Call the iterate method on all nodes in current adjacency list. Note plugin
 * data can still be NULL if the plugin data failed to parse the plugin data.
 *
 * @param pluginid the plugin identifier.
 * @param iterate_fn the iterate function invoked for plugin data for every
 * node.
 * @param udata passed as is to the iterqte function. Useful for getting results
 * out of the iteration.
 * NULL if there is no plugin data.
 * @return the size of the plugin data. 0 if there is no plugin data.
 */
void
hb_plugin_data_iterate_all(as_hb_plugin_id pluginid,
			   as_hb_plugin_data_iterate_fn iterate_fn, void* udata)
{
	HB_LOCK();

	as_hb_adjacecny_iterate_reduce_udata reduce_udata;
	reduce_udata.pluginid = pluginid;
	reduce_udata.iterate_fn = iterate_fn;
	reduce_udata.udata = udata;
	shash_reduce(g_hb.adjacency, hb_plugin_data_iterate_reduce,
		     &reduce_udata);

	HB_UNLOCK();
}
