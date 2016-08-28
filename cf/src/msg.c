/*
 * msg.c
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


//==========================================================
// Includes.
//

#include "msg.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_types.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_byte_order.h"

#include "dynbuf.h"
#include "fault.h"


//==========================================================
// Globals.
//

// Total number of "msg" objects allocated:
cf_atomic_int g_num_msgs = 0;

// Total number of "msg" objects allocated per type:
cf_atomic_int g_num_msgs_by_type[M_TYPE_MAX] = { 0 };

// Number of "msg" objects per type that can be allocated. (Default to -1,
// meaning there is no limit on allowed number of "msg" objects per type.)
static int64_t g_max_msgs_per_type = -1;


//==========================================================
// Forward declarations.
//

static size_t msg_get_wire_field_size(const msg_field_type type, size_t field_len);
static uint32_t msg_stamp_field(uint8_t *buf, const msg_field *mf);
static void msg_field_save(msg *m, msg_field *mf);
static msg_str_array *msg_str_array_create(int n_strs, int total_len);
static int msg_str_array_set(msg_str_array *str_a, int idx, const char *v);
static msg_buf_array *msg_buf_array_create(int n_bufs, int buf_len);
static int msg_buf_array_set(msg_buf_array *buf_a, int idx, const uint8_t *v, int len);
static int msg_str_array_get(msg_str_array *str_a, int idx, char **r, size_t *len);
static int msg_buf_array_get(const msg_buf_array *buf_a, int idx, uint8_t **r, size_t *len);


//==========================================================
// Public API - object accounting.
//

// Limit the maximum number of "msg" objects per type (-1 means unlimited.)
void
msg_set_max_msgs_per_type(int64_t max_msgs)
{
	g_max_msgs_per_type = max_msgs;
}


// Call this instead of freeing msg directly, to keep track of all msgs.
void
msg_put(msg *m)
{
	cf_atomic_int_decr(&g_num_msgs);
	cf_atomic_int_decr(&g_num_msgs_by_type[m->type]);
	cf_rc_free(m);
}


//==========================================================
// Public API - lifecycle.
//

int
msg_create(msg **m_r, msg_type type, const msg_template *mt, size_t mt_sz,
		size_t scratch_sz)
{
	// Place a limit on the number of "msg" objects of each type that may be
	// allocated at a given time. (The default value of -1 means no limit.)
	if (g_max_msgs_per_type > 0 &&
			cf_atomic_int_get(g_num_msgs_by_type[type]) >=
					g_max_msgs_per_type) {
		cf_warning(CF_MSG, "refusing to allocate more than %ld msg of type %d",
				g_max_msgs_per_type, type);
		return -1;
	}

	int mt_rows = (int)(mt_sz / sizeof(msg_template));

	if (mt_rows <= 0) {
		cf_crash(CF_MSG, "msg create: invalid template size parameter");
	}

	int max_id = 0;

	for (int i = 0; i < mt_rows; i++) {
		if (mt[i].id >= max_id) {
			max_id = mt[i].id;
		}
	}

	max_id++;

	size_t u_sz = sizeof(msg) + (sizeof(msg_field) * max_id);
	size_t a_sz = u_sz + scratch_sz;

	msg *m = cf_rc_alloc(a_sz);
	cf_assert(m, CF_MSG, CF_CRITICAL, "malloc");

	m->n_fields = (uint32_t)max_id;
	m->bytes_used = (uint32_t)u_sz;
	m->bytes_alloc = (uint32_t)a_sz;
	m->just_parsed = false;
	m->type = type;
	m->mt = mt;

	for (int i = 0; i < max_id; i++) {
		m->f[i].is_valid = false;
	}

	for (int i = 0; i < mt_rows; i++) {
		msg_field *f = &m->f[mt[i].id];

		f->id = mt[i].id;
		f->type = mt[i].type;
		f->free = false;
		f->is_set = false;
		f->is_valid = true;
	}

	*m_r = m;

	// Keep track of allocated msgs.
	cf_atomic_int_incr(&g_num_msgs);
	cf_atomic_int_incr(&g_num_msgs_by_type[type]);

	return 0;
}


void
msg_destroy(msg *m)
{
	if (0 == cf_rc_release(m)) {
		for (uint32_t i = 0; i < m->n_fields; i++) {
			if (m->f[i].is_valid && m->f[i].is_set) {
				if (m->f[i].free) {
					cf_free(m->f[i].u.any_buf);
					m->f[i].free = false;
				}
			}
		}

		msg_put(m);
	}
}


void
msg_incr_ref(msg *m)
{
	cf_rc_reserve(m);
}


void
msg_decr_ref(msg *m)
{
	cf_rc_release(m);
}


//==========================================================
// Public API - pack messages into flattened data.
//

// Current protocol:
// uint32_t size-in-bytes (not including this header, network byte order)
// uint16_t type (still included in the header)
//      2 byte - field id
// 		1 byte - field type
//      4 bytes - field size
//      [x] - field
//      (7 + field sz)

uint32_t
msg_get_wire_size(const msg *m)
{
	uint32_t sz = 6;

	for (uint32_t i = 0; i < m->n_fields; i++) {
		const msg_field *mf = &m->f[i];

		if (mf->is_valid && mf->is_set) {
			sz += msg_get_wire_field_size(mf->type, mf->field_len);
		}
	}

	return sz;
}

// Get the fixed wire size of input templates.
// mt - pointer to the templates.
// mt_len - number of templates.
int
msg_get_template_fixed_sz(const msg_template* mt, const size_t mt_len)
{
	// Include fixed header size.
	uint32_t sz = 6;

	for (int i = 0; i < mt_len; i++) {
			sz += msg_get_wire_field_size(mt[i].type, 0);
	}

	return sz;
}


int
msg_fillbuf(const msg *m, uint8_t *buf, size_t *buflen)
{
	// Figure out the size
	uint32_t sz = msg_get_wire_size(m);

	if (sz > *buflen) {
		*buflen = sz; // tell the caller how much you're really going to need
		return -2;
	}

	*buflen = sz;

	*(uint32_t *)buf = cf_swap_to_be32(sz - 6);
	buf += 4;

	*(uint16_t *)buf = cf_swap_to_be16(m->type);
	buf += 2;

	for (uint32_t i = 0; i < m->n_fields; i++) {
		const msg_field *mf = &m->f[i];

		if (mf->is_valid && mf->is_set) {
			buf += msg_stamp_field(buf, mf);
		}
	}

	return 0;
}


//==========================================================
// Public API - parse flattened data into messages.
//

int
msg_parse(msg *m, const uint8_t *buf, size_t buflen)
{
	if (buflen < 6) {
		return -2;
	}

	uint32_t len = cf_swap_from_be32(*(uint32_t *)buf);

	if (buflen < len + 6) {
		return -2;
	}

	buf += 4;

	uint16_t type = cf_swap_from_be16(*(uint16_t *)buf);

	if (m->type != type) {
		cf_warning(CF_MSG, "parsed type %d for msg type %d", type, m->type);
		return -1;
	}

	buf += 2;

	const uint8_t *eob = buf + len;

	while (buf < eob) {
		uint32_t id = (buf[0] << 8) | buf[1];

		buf += 2;

		msg_field *mf;

		if (id >= m->n_fields) {
			mf = NULL;
		}
		else {
			mf = &m->f[id];

			if (! mf->is_valid) {
				mf = NULL;
			}
		}

		msg_field_type ft = (msg_field_type)*buf++;
		uint32_t flen = cf_swap_from_be32(*(uint32_t *)buf);

		buf += 4;

		if (mf && ft != mf->type) {
			cf_warning(CF_MSG, "msg type %d: parsed type %d for field type %d",
					m->type, ft, mf->type);
			mf = NULL;
		}

		if (mf) {
			switch (mf->type) {
			case M_FT_INT32:
			case M_FT_UINT32:
				mf->u.ui32 = cf_swap_from_be32(*(uint32_t *)buf);
				break;
			case M_FT_INT64:
			case M_FT_UINT64:
				mf->u.ui64 = cf_swap_from_be64(*(uint64_t *)buf);
				break;
			case M_FT_STR:
			case M_FT_BUF:
			case M_FT_ARRAY_UINT32:
			case M_FT_ARRAY_UINT64:
			case M_FT_ARRAY_STR:
			case M_FT_ARRAY_BUF:
				mf->field_len = flen;
				mf->u.any_buf = (void *)buf;
				mf->free = false;
				break;
			default:
				cf_detail(CF_MSG, "msg_parse: field type %d not supported - skipping",
						mf->type);
				break;
			}

			mf->is_set = true;
		}

		buf += flen;
	}

	m->just_parsed = true;

	return 0;
}


int
msg_get_initial(uint32_t *size_r, msg_type *type_r, const uint8_t *buf,
		uint32_t buflen)
{
	if (buflen < 6) {
		return -2;
	}

	uint32_t size = cf_swap_from_be32(*(uint32_t *)buf);

	buf += 4;

	size += 6; // size does not include this header
	*size_r = size;

	uint16_t type = cf_swap_from_be16(*(uint16_t *)buf);

	*type_r = type;

	return 0;
}


void
msg_reset(msg *m)
{
	m->bytes_used = (m->n_fields * sizeof(msg_field)) + sizeof(msg);
	m->just_parsed = false;

	for (uint32_t i = 0; i < m->n_fields; i++) {
		msg_field *mf = &m->f[i];

		if (mf->is_valid && mf->is_set) {
			if (mf->free) {
				cf_free(mf->u.any_buf);
				mf->free = false;
			}

			mf->is_set = false;
		}
	}
}


void
msg_preserve_fields(msg *m, uint32_t n_field_ids, ...)
{
	bool reflect[m->n_fields];

	for (uint32_t i = 0; i < m->n_fields; i++) {
		reflect[i] = false;
	}

	va_list argp;
	va_start(argp, n_field_ids);

	for (uint32_t n = 0; n < n_field_ids; n++) {
		reflect[va_arg(argp, int)] = true;
	}

	va_end(argp);

	for (uint32_t i = 0; i < m->n_fields; i++) {
		msg_field *mf = &m->f[i];

		if (mf->is_valid && mf->is_set) {
			if (reflect[i]) {
				if (m->just_parsed) {
					msg_field_save(m, mf);
				}
			}
			else {
				mf->is_set = false;
			}
		}
	}

	m->just_parsed = false;
}


void
msg_preserve_all_fields(msg *m)
{
	if (! m->just_parsed) {
		return;
	}

	for (uint32_t i = 0; i < m->n_fields; i++) {
		msg_field *mf = &m->f[i];

		if (mf->is_valid && mf->is_set) {
			msg_field_save(m, mf);
		}
	}

	m->just_parsed = false;
}


//==========================================================
// Public API - set fields in messages.
//

int
msg_set_uint32(msg *m, int field_id, uint32_t v)
{
	m->f[field_id].is_set = true;
	m->f[field_id].u.ui32 = v;

	return 0;
}


int
msg_set_int32(msg *m, int field_id, int32_t v)
{
	m->f[field_id].is_set = true;
	m->f[field_id].u.i32 = v;

	return 0;
}


int
msg_set_uint64(msg *m, int field_id, uint64_t v)
{
	m->f[field_id].is_set = true;
	m->f[field_id].u.ui64 = v;

	return 0;
}


int
msg_set_int64(msg *m, int field_id, int64_t v)
{
	m->f[field_id].is_set = true;
	m->f[field_id].u.i64 = v;

	return 0;
}


int
msg_set_str(msg *m, int field_id, const char *v, msg_set_type type)
{
	msg_field *mf = &m->f[field_id];

	if (mf->is_set) {
		if (mf->free) {
			cf_free(mf->u.any_buf);
			mf->free = false;
		}
	}

	mf->field_len = strlen(v) + 1;

	if (MSG_SET_COPY == type) {
		size_t len = mf->field_len;

		if (m->bytes_alloc - m->bytes_used >= len) {
			mf->u.str = (char *)m + m->bytes_used;
			m->bytes_used += len;
			mf->free = false;
			memcpy(mf->u.str, v, len);
		}
		else {
			mf->u.str = cf_strdup(v);
			cf_assert(mf->u.str, CF_MSG, CF_CRITICAL, "malloc");
			mf->free = true;
		}
	}
	else if (MSG_SET_HANDOFF_MALLOC == type) {
		mf->u.str = (char *)v;
		mf->free = v != NULL;

		if (! v) {
			cf_warning(CF_MSG, "handoff malloc with null pointer");
		}
	}

	mf->is_set = true;

	return 0;
}


int
msg_set_buf(msg *m, int field_id, const uint8_t *v, size_t len,
		msg_set_type type)
{
	msg_field *mf = &m->f[field_id];

	if (mf->is_set) {
		if (mf->free) {
			cf_free(mf->u.any_buf);
			mf->free = false;
		}
	}

	mf->field_len = len;

	if (MSG_SET_COPY == type) {
		if (m->bytes_alloc - m->bytes_used >= len) {
			mf->u.buf = (uint8_t *)m + m->bytes_used;
			m->bytes_used += len;
			mf->free = false;
		}
		else {
			mf->u.buf = cf_malloc(len);
			cf_assert(mf->u.buf, CF_MSG, CF_CRITICAL, "malloc");
			mf->free = true;
		}

		memcpy(mf->u.buf, v, len);

	}
	else if (type == MSG_SET_HANDOFF_MALLOC) {
		mf->u.buf = (void *)v;
		mf->free = v != NULL;

		if (! v) {
			cf_warning(CF_MSG, "handoff malloc with null pointer");
		}
	}

	mf->is_set = true;

	return 0;
}


int
msg_set_uint32_array_size(msg *m, int field_id, int size)
{
	msg_field *mf = &m->f[field_id];

	mf->field_len = size * sizeof(uint32_t);

	if (mf->is_set) {
		mf->u.ui32_a = cf_realloc(mf->u.ui32_a, mf->field_len);

		if (! mf->u.ui32_a) {
			return -1;
		}
	}
	else {
		mf->u.ui32_a = cf_malloc(mf->field_len);

		if (! mf->u.ui32_a) {
			return -1;
		}

		mf->is_set = true;
	}

	mf->free = true;

	return 0;
}


int
msg_set_uint32_array(msg *m, int field_id, int index, uint32_t v)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		return -1;
	}

	if (index >= mf->field_len >> 2) {
		return -1;
	}

	mf->u.ui32_a[index] = cf_swap_to_be32(v);

	return 0;
}


int
msg_set_uint64_array_size(msg *m, int field_id, int size)
{
	msg_field *mf = &m->f[field_id];

	mf->field_len = size * sizeof(uint64_t);

	if (mf->is_set) {
		mf->u.ui64_a = cf_realloc(mf->u.ui64_a, mf->field_len);

		if (! mf->u.ui64_a) {
			return -1;
		}
	}
	else {
		mf->u.ui64_a = cf_malloc(mf->field_len);

		if (! mf->u.ui64_a) {
			return -1;
		}

		mf->is_set = true;
	}

	mf->free = true;

	return 0;
}


int
msg_set_uint64_array(msg *m, int field_id, int index, const uint64_t v)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		return -1;
	}

	if (index >= mf->field_len >> 3) {
		return -1;
	}

	mf->u.ui64_a[index] = cf_swap_to_be64(v);

	return 0;
}


int
msg_set_str_array_size(msg *m, int field_id, int size, int total_len)
{
	if (size < 0 || total_len < 0) {
		cf_crash(CF_MSG, "illegal size parameters");
		return -1;
	}

	if (size == 0 || total_len == 0) {
		// If it is zero, do not allocate memory.
		// Receiver will not process this field.
		return 0;
	}

	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		msg_str_array *str_a = msg_str_array_create(size, total_len);

		if (! str_a) {
			return -1;
		}

		mf->u.str_a = str_a;
		mf->free = true;
		mf->field_len = str_a->used_size;
		mf->is_set = true;
	}
	else {
		cf_info(CF_MSG, "msg_str_array: does not support resize");
		return -1;
	}

	return 0;
}


int
msg_set_str_array(msg *m, int field_id, int index, const char *v)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		cf_warning(CF_MSG, "msg_str_array: must set length first");
		return -1;
	}

	msg_str_array *str_a = mf->u.str_a;

	if (0 != msg_str_array_set(str_a, index, v)) {
		return -1;
	}

	mf->field_len = str_a->used_size;

	return 0;
}


int
msg_set_buf_array_size(msg *m, int field_id, int size, int elem_size)
{
	if (size <= 0 || elem_size <= 0) {
		cf_warning(CF_MSG, "Illegal size parameters");
		return -1;
	}

	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		msg_buf_array *buf_a = msg_buf_array_create(size, elem_size);

		if (! buf_a) {
			return -1;
		}

		mf->u.buf_a = buf_a;
		mf->free = true;
		mf->field_len = buf_a->used_size;
		mf->is_set = true;
	}
	else {
		cf_info(CF_MSG, "msg_buf_array: does not support resize");
		return -1;
	}

	return 0;
}


int
msg_set_buf_array(msg *m, int field_id, int index, const uint8_t *v, size_t len)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		cf_warning(CF_MSG, "msg_buf_array: must set length first");
		return -1;
	}

	msg_buf_array *buf_a = mf->u.buf_a;

	if (0 != msg_buf_array_set(buf_a, index, v, len)) {
		return -1;
	}

	mf->field_len = buf_a->used_size;

	return 0;
}


//==========================================================
// Public API - get fields from messages.
//

int
msg_get_uint32(const msg *m, int field_id, uint32_t *r)
{
	if (! m->f[field_id].is_set) {
		*r = 0;
		return -2;
	}

	*r = m->f[field_id].u.ui32;

	return 0;
}


int
msg_get_int32(const msg *m, int field_id, int32_t *r)
{
	if (! m->f[field_id].is_set) {
		*r = 0;
		return -2;
	}

	*r = m->f[field_id].u.i32;

	return 0;
}


int
msg_get_uint64(const msg *m, int field_id, uint64_t *r)
{
	if (! m->f[field_id].is_set) {
		*r = 0;
		return -2;
	}

	*r = m->f[field_id].u.ui64;

	return 0;
}


int
msg_get_int64(const msg *m, int field_id, int64_t *r)
{
	if (! m->f[field_id].is_set) {
		*r = 0;
		return -2;
	}

	*r = m->f[field_id].u.i64;

	return 0;
}


// Returned 'len' includes null terminator, i.e. strlen + 1.
int
msg_get_str(const msg *m, int field_id, char **r, size_t *len,
		msg_get_type type)
{
	if (! m->f[field_id].is_set) {
		*r = 0;

		if (len) {
			*len = 0;
		}

		return -2;
	}

	if (MSG_GET_DIRECT == type) {
		*r = m->f[field_id].u.str;
	}
	else if (MSG_GET_COPY_MALLOC == type) {
		*r = cf_strdup(m->f[field_id].u.str);
		cf_assert(*r, CF_MSG, CF_CRITICAL, "malloc");
	}
	else {
		cf_crash(CF_MSG, "msg_get_str: illegal msg_get_type");
		return -2;
	}

	if (len) {
		*len = m->f[field_id].field_len;
	}

	return 0;
}


int
msg_get_buf(const msg *m, int field_id, uint8_t **r, size_t *len,
		msg_get_type type)
{
	if (! m->f[field_id].is_set) {
		*r = 0;

		if (len) {
			*len = 0;
		}

		return -2;
	}

	if (MSG_GET_DIRECT == type) {
		*r = m->f[field_id].u.buf;
	}
	else if (MSG_GET_COPY_MALLOC == type) {
		*r = cf_malloc(m->f[field_id].field_len);
		cf_assert(*r, CF_MSG, CF_CRITICAL, "malloc");
		memcpy(*r, m->f[field_id].u.buf, m->f[field_id].field_len);
	}
	else {
		cf_crash(CF_MSG, "msg_get_buf: illegal msg_get_type");
		return -2;
	}

	if (len) {
		*len = m->f[field_id].field_len;
	}

	return 0;
}

bool
msg_is_set(const msg* m, int field_id)
{
	if (field_id >= m->n_fields) {
		return false;
	}
	return m->f[field_id].is_valid && m->f[field_id].is_set;
}

int
msg_get_uint32_array(msg *m, int field_id, int index, uint32_t *r)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		return -1;
	}

	*r = cf_swap_from_be32(mf->u.ui32_a[index]);

	return 0;
}


int
msg_get_uint64_array_size(msg *m, int field_id, int *size)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		return -1;
	}

	*size = mf->field_len >> 3;

	return 0;
}


int
msg_get_uint64_array(msg *m, int field_id, int index, uint64_t *r)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		return -1;
	}

	*r = cf_swap_from_be64(mf->u.ui64_a[index]);

	return 0;
}


int
msg_get_str_array(msg *m, int field_id, int index, char **r, size_t *len,
		msg_get_type type)
{
	msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		cf_info(CF_MSG, "msg_str_array: field not set");
		return -2;
	}

	if (! mf->u.str_a) {
		cf_info(CF_MSG, "no str array");
		return -1;
	}

	msg_str_array *str_a = mf->u.str_a;

	char *b;

	if (0 != msg_str_array_get(str_a, index, &b, len)) {
		return -1;
	}

	switch (type) {
	case MSG_GET_DIRECT:
		*r = b;
		break;
	case MSG_GET_COPY_MALLOC:
		*r = cf_malloc(*len);
		memcpy(*r, b, *len);
		break;
	default:
		cf_crash(CF_MSG, "unexpected msg_get_type");
		break;
	}

	return 0;
}


int
msg_get_buf_array_size(const msg *m, int field_id, int *size)
{
	const msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		cf_info(CF_MSG, "msg_buf_array: field not set");
		return -2;
	}

	if (! mf->u.buf_a) {
		cf_info(CF_MSG, "no buf array");
		return -1;
	}

	msg_buf_array *buf_a = mf->u.buf_a;

	*size = buf_a->len;

	return 0;
}


int
msg_get_buf_array(const msg *m, int field_id, int index, uint8_t **r,
		size_t *len, msg_get_type type)
{
	const msg_field *mf = &m->f[field_id];

	if (! mf->is_set) {
		cf_info(CF_MSG, "msg_buf_array: field not set");
		return -2;
	}

	if (! mf->u.buf_a) {
		cf_info(CF_MSG, "no buf array");
		return -1;
	}

	const msg_buf_array *buf_a = mf->u.buf_a;

	uint8_t *b;

	if (0 != msg_buf_array_get(buf_a, index, &b, len)) {
		return -1;
	}

	switch (type) {
	case MSG_GET_DIRECT:
		*r = b;
		break;
	case MSG_GET_COPY_MALLOC:
		*r = cf_malloc(*len);
		memcpy(*r, b, *len);
		break;
	default:
		cf_crash(CF_MSG, "unexpected msg_get_type");
		break;
	}

	return 0;
}


//==========================================================
// Public API - debugging only.
//

void
msg_dump(const msg *m, const char *info)
{
	cf_info(CF_MSG, "msg_dump: %s: msg %p rc %d n-fields %u bytes-used %u bytes-alloc'd %u type %d mt %p",
			info, m, (int)cf_rc_count((void*)m), m->n_fields, m->bytes_used,
			m->bytes_alloc, m->type, m->mt);

	for (uint32_t i = 0; i < m->n_fields; i++) {
		const msg_field *mf =  &m->f[i];

		cf_info(CF_MSG, "mf %02u: id %u is-valid %d is-set %d",
				i, mf->id, mf->is_valid, mf->is_set);

		if (mf->is_valid && mf->is_set) {
			switch(mf->type) {
			case M_FT_INT32:
				cf_info(CF_MSG, "   type INT32 value %d", mf->u.i32);
				break;
			case M_FT_UINT32:
				cf_info(CF_MSG, "   type UINT32 value %u", mf->u.ui32);
				break;
			case M_FT_INT64:
				cf_info(CF_MSG, "   type INT64 value %ld", mf->u.i64);
				break;
			case M_FT_UINT64:
				cf_info(CF_MSG, "   type UINT64 value %lu", mf->u.ui64);
				break;
			case M_FT_STR:
				cf_info(CF_MSG, "   type STR len %u free %c value %s",
						mf->field_len, mf->free ? 't' : 'f', mf->u.str);
				break;
			case M_FT_BUF:
				cf_info_binary(CF_MSG, mf->u.buf, mf->field_len,
						CF_DISPLAY_HEX_COLUMNS,
						"   type BUF len %u free %c value ",
						mf->field_len, mf->free ? 't' : 'f');
				break;
			case M_FT_ARRAY_UINT32:
				cf_info(CF_MSG, "   type ARRAY_UINT32: len %u n-uint32 %u free %c",
						mf->field_len, mf->field_len >> 2,
						mf->free ? 't' : 'f');
				{
					int n_ints = mf->field_len >> 2;
					for (int j = 0; j < n_ints; j++) {
						cf_info(CF_MSG, "      idx %d value %u",
								j, ntohl(mf->u.ui32_a[j]));
					}
				}
				break;
			case M_FT_ARRAY_UINT64:
				cf_info(CF_MSG, "   type ARRAY_UINT64: len %u n-uint64 %u free %c",
						mf->field_len, mf->field_len >> 3,
						mf->free ? 't' : 'f');
				{
					int n_ints = mf->field_len >> 3;
					for (int j = 0; j < n_ints; j++) {
						cf_info(CF_MSG, "      idx %d value %lu",
								j, __bswap_64(mf->u.ui64_a[j]));
					}
				}
				break;
			default:
				cf_info(CF_MSG, "   type %d unknown", mf->type);
				break;
			}
		}
	}
}


//==========================================================
// Local helpers.
//

static size_t
msg_get_wire_field_size(const msg_field_type type, size_t field_len)
{
	switch (type) {
	case M_FT_INT32:
	case M_FT_UINT32:
		return 4 + 7;
	case M_FT_INT64:
	case M_FT_UINT64:
		return 8 + 7;
	case M_FT_STR:
	case M_FT_BUF:
	case M_FT_ARRAY_UINT32:
	case M_FT_ARRAY_UINT64:
	case M_FT_ARRAY_STR:
	case M_FT_ARRAY_BUF:
		return field_len + 7;
	default:
		cf_crash(CF_MSG, "unexpected field type %d", type);
		break;
	}

	return 0;
}


// Returns the number of bytes written.
static uint32_t
msg_stamp_field(uint8_t *buf, const msg_field *mf)
{
	buf[0] = (mf->id >> 8) & 0xff;
	buf[1] = mf->id & 0xff;
	buf += 2;

	*buf++ = (msg_field_type)mf->type;

	uint32_t flen;
	uint32_t *p_flen = (uint32_t *)buf;

	buf += 4;

	switch(mf->type) {
	case M_FT_INT32:
	case M_FT_UINT32:
		flen = 4;
		*(uint32_t *)buf = cf_swap_to_be32(mf->u.ui32);
		break;
	case M_FT_INT64:
	case M_FT_UINT64:
		flen = 8;
		*(uint64_t *)buf = cf_swap_to_be64(mf->u.ui64);
		break;
	case M_FT_STR:
	case M_FT_BUF:
	case M_FT_ARRAY_UINT32:
	case M_FT_ARRAY_UINT64:
	case M_FT_ARRAY_STR:
	case M_FT_ARRAY_BUF:
		flen = mf->field_len;
		memcpy(buf, mf->u.any_buf, flen);
		break;
	default:
		cf_crash(CF_MSG, "unexpected field type %d", mf->type);
		return 0;
	}

	*p_flen = cf_swap_to_be32(flen);

	return 7 + flen;
}


static void
msg_field_save(msg *m, msg_field *mf)
{
	switch (mf->type) {
	case M_FT_INT32:
	case M_FT_UINT32:
	case M_FT_INT64:
	case M_FT_UINT64:
		break;
	case M_FT_STR:
	case M_FT_BUF:
	case M_FT_ARRAY_UINT32:
	case M_FT_ARRAY_UINT64:
	case M_FT_ARRAY_STR:
	case M_FT_ARRAY_BUF:
		// Should only preserve received messages where buffer pointers point
		// directly into a fabric buffer.
		cf_assert(! mf->free, CF_MSG, CF_CRITICAL, "invalid msg preserve");

		if (m->bytes_alloc - m->bytes_used >= mf->field_len) {
			void *buf = ((uint8_t *)m) + m->bytes_used;

			memcpy(buf, mf->u.any_buf, mf->field_len);
			mf->u.any_buf = buf;
			m->bytes_used += mf->field_len;
			mf->free = false;
		}
		else {
			void *buf = cf_malloc(mf->field_len);
			cf_assert(buf, CF_MSG, CF_CRITICAL, "malloc");

			memcpy(buf, mf->u.any_buf, mf->field_len);
			mf->u.any_buf = buf;
			mf->free = true;
		}
		break;
	default:
		break;
	}
}


static msg_str_array *
msg_str_array_create(int n_strs, int total_len)
{
	int len = sizeof(msg_str_array) + (n_strs * sizeof(uint32_t)) + total_len;
	msg_str_array *str_a = cf_malloc(len);

	if (! str_a) {
		return NULL;
	}

	str_a->alloc_size = len;
	str_a->used_size = sizeof(msg_str_array) + (n_strs * sizeof(uint32_t));

	str_a->len = n_strs;

	for (int i = 0; i < n_strs; i++) {
		str_a->offset[i] = 0;
	}

	return str_a;
}


static int
msg_str_array_set(msg_str_array *str_a, int idx, const char *v)
{
	if (idx >= str_a->len) {
		cf_info(CF_MSG, "msg_str_array: idx %u too large", idx);
		return -1;
	}

	size_t len = strlen(v) + 1;

	if (str_a->used_size + len > str_a->alloc_size) {
		cf_info(CF_MSG, "todo: allow resize of outgoing str arrays");
		return -1;
	}

	str_a->offset[idx] = str_a->used_size;

	char *data = (char *)str_a + str_a->offset[idx];

	strncpy(data, v, len);
	str_a->used_size += len;

	return 0;
}


static msg_buf_array *
msg_buf_array_create(int n_bufs, int buf_len)
{
	int len = sizeof(msg_buf_array) +
			(n_bufs * (sizeof(uint32_t) + buf_len + sizeof(msg_pbuf)));
	msg_buf_array *buf_a = cf_malloc( len );

	if (! buf_a) {
		return NULL;
	}

	buf_a->alloc_size = len;
	buf_a->used_size = sizeof(msg_buf_array) + (n_bufs * sizeof(uint32_t));

	buf_a->len = n_bufs;

	for (int i = 0; i < n_bufs; i++) {
		buf_a->offset[i] = 0;
	}

	return buf_a;
}


static int
msg_buf_array_set(msg_buf_array *buf_a, int idx, const uint8_t *v, int len)
{
	if (idx >= buf_a->len) {
		cf_info(CF_MSG, "msg_buf_array: idx %u too large", idx);
		return -1;
	}

	if (buf_a->used_size + len + sizeof(msg_pbuf) > buf_a->alloc_size) {
		cf_info(CF_MSG, "todo: allow resize of outgoing buf arrays");
		return -1;
	}

	buf_a->offset[idx] = buf_a->used_size;

	msg_pbuf *pbuf = (msg_pbuf *)((uint8_t *)buf_a + buf_a->used_size);

	pbuf->len = len;
	memcpy(pbuf->data, v, len);

	buf_a->used_size += len + sizeof(msg_pbuf);

	return 0;
}


static int
msg_str_array_get(msg_str_array *str_a, int idx, char **r, size_t *len)
{
	if (idx > str_a->len) {
		cf_info(CF_MSG, "msg_str_array_get: idx %u too large", idx);
		return -1;
	}

	if (str_a->offset[idx] == 0) {
		cf_info(CF_MSG, "msg_str_array: idx %u not set", idx);
		return -2;
	}

	*r = (char *)str_a + str_a->offset[idx];
	*len = strlen(*r) + 1;

	return 0;
}


static int
msg_buf_array_get(const msg_buf_array *buf_a, int idx, uint8_t **r, size_t *len)
{
	if (idx > buf_a->len) {
		cf_info(CF_MSG, "msg_buf_array_get: idx %u too large", idx);
		return -1;
	}

	if (buf_a->offset[idx] == 0) {
		cf_info(CF_MSG, "msg_buf_array: idx %u not set", idx);
		return -2;
	}

	msg_pbuf *pbuf = (msg_pbuf *)((uint8_t *)buf_a + buf_a->offset[idx]);

	*len = pbuf->len;
	*r = pbuf->data;

	return 0;
}
