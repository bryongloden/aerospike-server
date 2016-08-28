/*
 * msg.h
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

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <citrusleaf/cf_atomic.h>
#include <citrusleaf/cf_types.h>
#include "dynbuf.h"


//==========================================================
// Typedefs & constants.
//

// These values are used on the wire - don't change them.
typedef enum msg_field_type_t {
	M_FT_INT32 = 1,
	M_FT_UINT32 = 2,
	M_FT_INT64 = 3,
	M_FT_UINT64 = 4,
	M_FT_STR = 5,
	M_FT_BUF = 6,
	M_FT_ARRAY_UINT32 = 7,
	M_FT_ARRAY_UINT64 = 8,
	M_FT_ARRAY_BUF = 9,
	M_FT_ARRAY_STR = 10
} msg_field_type;

typedef enum msg_type_t {
	M_TYPE_FABRIC = 0,
	M_TYPE_HEARTBEAT_V2 = 1,
	M_TYPE_PAXOS = 2,
	M_TYPE_MIGRATE = 3,
	M_TYPE_PROXY = 4,
	M_TYPE_HEARTBEAT = 5,
	M_TYPE_UNUSED_6 = 6,
	M_TYPE_RW = 7,
	M_TYPE_INFO = 8,
	M_TYPE_UNUSED_9 = 9,
	M_TYPE_UNUSED_10 = 10,
	M_TYPE_XDR = 11,
	M_TYPE_UNUSED_12 = 12,
	M_TYPE_UNUSED_13 = 13,
	M_TYPE_UNUSED_14 = 14,
	M_TYPE_SMD = 15,
	M_TYPE_UNUSED_16 = 16,
	M_TYPE_UNUSED_17 = 17,
	M_TYPE_MAX = 18
} msg_type;

typedef struct msg_template_s {
	int				id;
	msg_field_type	type;
} msg_template;

typedef struct msg_str_array_s {
	uint32_t	alloc_size;	// number of bytes allocated
	uint32_t	used_size;	// bytes used in the string array
	uint32_t	len;		// number of string offsets
	uint32_t	offset[];	// array of pointers to the strings
} msg_str_array;

typedef struct msg_pbuf_s {
	uint32_t	len;
	uint8_t		data[];
} msg_pbuf;

typedef struct msg_buf_array_s {
	uint32_t	alloc_size;	// number of bytes allocated
	uint32_t	used_size;	// bytes used in the buffer array
	uint32_t	len;		// number of string offsets
	uint32_t	offset[];	// array of pointers to the buffers
} msg_buf_array;

typedef struct msg_field_t {
	int		 		id;
	msg_field_type	type;
	uint32_t 		field_len;
	bool			is_valid;
	bool			is_set;
	bool 			free;
	union {
		uint32_t		ui32;
		int32_t			i32;
		uint64_t		ui64;
		int64_t			i64;
		char 			*str;
		uint8_t			*buf;
		uint32_t		*ui32_a;
		uint64_t		*ui64_a;
		msg_str_array	*str_a;
		msg_buf_array	*buf_a;
		void			*any_buf;
	} u;
} msg_field;

typedef struct msg_t {
	uint32_t			n_fields;
	uint32_t			bytes_used;
	uint32_t			bytes_alloc;
	bool				just_parsed; // fields point into fabric buffer
	msg_type			type;
	const msg_template	*mt;
	msg_field			f[];
} msg;

typedef enum {
	MSG_GET_DIRECT,
	MSG_GET_COPY_MALLOC
} msg_get_type;

typedef enum {
	MSG_SET_HANDOFF_MALLOC,
	MSG_SET_COPY
} msg_set_type;


//==========================================================
// Globals.
//

extern cf_atomic_int g_num_msgs;
extern cf_atomic_int g_num_msgs_by_type[M_TYPE_MAX];


//==========================================================
// Public API.
//

//------------------------------------------------
// Object accounting.
//

// Limit the maximum number of "msg" objects per type (-1 means unlimited.)
void msg_set_max_msgs_per_type(int64_t max_msgs);

// Free up a "msg" object. Call this function instead of freeing the msg
// directly in order to keep track of all msgs.
void msg_put(msg *m);

//------------------------------------------------
// Lifecycle.
//

int msg_create(msg **m, msg_type type, const msg_template *mt, size_t mt_sz, size_t scratch_sz);
void msg_destroy(msg *m);

void msg_incr_ref(msg *m);
void msg_decr_ref(msg *m);

//------------------------------------------------
// Pack messages into flattened data.
//

uint32_t msg_get_wire_size(const msg *m);
// Get the fixed wire size of input templates.
// mt - pointer to the templates.
// mt_len - number of templates.
int msg_get_template_fixed_sz(const msg_template* mt, const size_t mt_len);

int msg_fillbuf(const msg *m, uint8_t *buf, size_t *buflen);

//------------------------------------------------
// Parse flattened data into messages.
//

int msg_parse(msg *m, const uint8_t *buf, size_t buflen);
int msg_get_initial(uint32_t *size, msg_type *type, const uint8_t *buf, uint32_t buflen);

void msg_reset(msg *m);
void msg_preserve_fields(msg *m, uint32_t n_field_ids, ...);
void msg_preserve_all_fields(msg *m);

//------------------------------------------------
// Set fields in messages.
//
int msg_set_uint32(msg *m, int field_id, uint32_t v);
int msg_set_int32(msg *m, int field_id, int32_t v);
int msg_set_uint64(msg *m, int field_id, uint64_t v);
int msg_set_int64(msg *m, int field_id, int64_t v);
int msg_set_str(msg *m, int field_id, const char *v, msg_set_type type);
int msg_set_buf(msg *m, int field_id, const uint8_t *v, size_t len, msg_set_type type);

int msg_set_uint32_array_size(msg *m, int field_id, int size);
int msg_set_uint32_array(msg *m, int field_id, int index, uint32_t v);
int msg_set_uint64_array_size(msg *m, int field_id, int size);
int msg_set_uint64_array(msg *m, int field_id, int index, uint64_t v);
int msg_set_str_array_size(msg *m, int field_id, int size, int total_len);
int msg_set_str_array(msg *m, int field_id, int index, const char *v);
int msg_set_buf_array_size(msg *m, int field_id, int size, int elem_size);
int msg_set_buf_array(msg *m, int field_id, int index, const uint8_t *v, size_t len);

//------------------------------------------------
// Get fields from messages.
//
bool msg_is_set(const msg *m, int field_id);
int msg_get_uint32(const msg *m, int field_id, uint32_t *r);
int msg_get_int32(const msg *m, int field_id, int32_t *r);
int msg_get_uint64(const msg *m, int field_id, uint64_t *r);
int msg_get_int64(const msg *m, int field_id, int64_t *r);
int msg_get_str(const msg *m, int field_id, char **r, size_t *len, msg_get_type type);
int msg_get_buf(const msg *m, int field_id, uint8_t **r, size_t *len, msg_get_type type);

int msg_get_uint32_array(msg *m, int field_id, int index, uint32_t *r);
int msg_get_uint64_array_size(msg *m, int field_id, int *size);
int msg_get_uint64_array(msg *m, int field_id, int index, uint64_t *r);
int msg_get_str_array(msg *m, int field_id, int index, char **r, size_t *len, msg_get_type type);
int msg_get_buf_array_size(const msg *m, int field_id, int *size);
int msg_get_buf_array(const msg *m, int field_id, int index, uint8_t **r, size_t *len, msg_get_type type);


//==========================================================
// Debugging API.
//

void msg_dump(const msg *m, const char *info);
