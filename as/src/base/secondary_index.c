/*
 * secondary_index.c
 *
 * Copyright (C) 2012-2015 Aerospike, Inc.
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
 * SYNOPSIS
 * Abstraction to support secondary indexes with multiple implementations.
 * Currently there are two variants of secondary indexes supported.
 *
 * -  Aerospike Index B-tree, this is full fledged index implementation and
 *    maintains its own metadata and data structure for list of those indexes.
 *
 * -  Citrusleaf foundation indexes which are bare bone tree implementation
 *    with ability to insert delete update indexes. For these the current code
 *    manage all the data structure to manage different trees. [Will be
 *    implemented when required]
 *
 * This file implements all the translation function which can be called from
 * citrusleaf to prepare to do the operations on secondary index. Also
 * implements locking to make Aerospike Index (single threaded) code multi threaded.
 *
 */

/* Code flow --
 *
 * DDLs
 *
 * as_sindex_create --> ai_btree_create
 *
 * as_sindex_destroy --> Releases the si and change the state to AS_SINDEX_DESTROY
 *
 * BOOT INDEX
 *
 * as_sindex_boot_populateall --> If fast restart or data in memory and load at start up --> as_sbld_build_all
 *
 * SBIN creation
 *
 * as_sindex_sbins_from_rd  --> (For every bin in the record) as_sindex_sbins_from_bin
 *
 * as_sindex_sbins_from_bin -->  as_sindex_sbins_from_bin_buf
 *
 * as_sindex_sbins_from_bin_buf --> (For every macthing sindex) --> as_sindex_sbin_from_sindex
 *
 * as_sindex_sbin_from_sindex --> (If bin value macthes with sindex defn) --> as_sindex_add_asval_to_itype_sindex
 *
 * SBIN updates
 *
 * as_sindex_update_by_sbin --> For every sbin --> as_sindex__op_by_sbin
 *
 * as_sindex__op_by_sbin --> If op == AS_SINDEX_OP_INSERT --> ai_btree_put
 *                       |
 *                       --> If op == AS_SINDEX_OP_DELETE --> ai_btree_delete
 *
 * DMLs using RECORD
 *
 * as_sindex_put_rd --> For each bin in the record --> as_sindex_sbin_from_sindex
 *
 * as_sindex_putall_rd --> For each sindex --> as_sindex_put_rd
 *
 */

#include "base/secondary_index.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_queue.h"

#include "aerospike/as_arraylist.h"
#include "aerospike/as_arraylist_iterator.h"
#include "aerospike/as_buffer.h"
#include "aerospike/as_hashmap.h"
#include "aerospike/as_hashmap_iterator.h"
#include "aerospike/as_msgpack.h"
#include "aerospike/as_pair.h"
#include "aerospike/as_serializer.h"
#include "aerospike/as_val.h"

#include "ai_btree.h"
#include "ai_globals.h"
#include "bt_iterator.h"
#include "cf_str.h"
#include "fault.h"

#include "base/cdt.h"
#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/stats.h"
#include "base/system_metadata.h"
#include "base/thr_sindex.h"
#include "base/thr_info.h"
#include "geospatial/geospatial.h"
#include "transaction/udf.h"


#define SINDEX_CRASH(str, ...) \
	cf_crash(AS_SINDEX, "SINDEX_ASSERT: "str, ##__VA_ARGS__);

#define AS_SINDEX_PROP_KEY_SIZE (AS_SET_NAME_MAX_SIZE + 20) // setname_binid_typeid


// ************************************************************************************************
//                                        BINID HAS SINDEX
// Maintains a bit array where binid'th bit represents the existence of atleast one index over the
// bin with bin id as binid.
// Set, reset should be called under SINDEX_GWLOCK
// get should be called under SINDEX_GRLOCK

void
as_sindex_set_binid_has_sindex(as_namespace *ns, int binid)
{
	int index     = binid / 32;
	uint32_t temp = ns->binid_has_sindex[index];
	temp         |= (1 << (binid % 32));
	ns->binid_has_sindex[index] = temp;
}

void
as_sindex_reset_binid_has_sindex(as_namespace *ns, int binid)
{
	int i          = 0;
	int j          = 0;
	as_sindex * si = NULL;

	while (i < AS_SINDEX_MAX && j < ns->sindex_cnt) {
		si = &ns->sindex[i];
		if (si != NULL) {
			if (si->state == AS_SINDEX_ACTIVE) {
				j++;
				if (si->imd->binid == binid) {
					return;
				}
			}
		}
		i++;
	}

	int index     = binid / 32;
	uint32_t temp = ns->binid_has_sindex[index];
	temp         &= ~(1 << (binid % 32));
	ns->binid_has_sindex[index] = temp;
}

bool
as_sindex_binid_has_sindex(as_namespace *ns, int binid)
{
	int index      = binid / 32;
	uint32_t temp  = ns->binid_has_sindex[index];
	return (temp & (1 << (binid % 32))) ? true : false;
}
//                                     END - BINID HAS SINDEX
// ************************************************************************************************
// ************************************************************************************************
//                                             UTILITY
// Translation from sindex error code to string. In alphabetic order
const char *as_sindex_err_str(int op_code) {
	switch(op_code) {
		case AS_SINDEX_ERR:                     return "ERR GENERIC";
		case AS_SINDEX_ERR_BIN_NOTFOUND:        return "BIN NOT FOUND";
		case AS_SINDEX_ERR_FOUND:               return "INDEX FOUND";
		case AS_SINDEX_ERR_INAME_MAXLEN:        return "INDEX NAME EXCEED MAX LIMIT";
		case AS_SINDEX_ERR_MAXCOUNT:            return "INDEX COUNT EXCEEDS MAX LIMIT";
		case AS_SINDEX_ERR_NOTFOUND:            return "NO INDEX";
		case AS_SINDEX_ERR_NOT_READABLE:        return "INDEX NOT READABLE";
		case AS_SINDEX_ERR_NO_MEMORY:           return "NO MEMORY";
		case AS_SINDEX_ERR_PARAM:               return "ERR PARAM";
		case AS_SINDEX_ERR_SET_MISMATCH:        return "SET MISMATCH";
		case AS_SINDEX_ERR_TYPE_MISMATCH:       return "KEY TYPE MISMATCH";
		case AS_SINDEX_ERR_UNKNOWN_KEYTYPE:     return "UNKNOWN KEYTYPE";
		case AS_SINDEX_OK:                      return "OK";
		default:                                return "Unknown Code";
	}
}

inline bool as_sindex_isactive(as_sindex *si)
{
	if (!si) {
		cf_warning(AS_SINDEX, "si is null in as_sindex_isactive");
		return FALSE;
	}
	bool ret;
	if (si->state == AS_SINDEX_ACTIVE) {
		ret = TRUE;
	} else {
		ret = FALSE;
	}
	return ret;
}

// Translation from sindex internal error code to generic client visible Aerospike error code
uint8_t as_sindex_err_to_clienterr(int err, char *fname, int lineno) {
	switch(err) {
		case AS_SINDEX_ERR_FOUND:        return AS_PROTO_RESULT_FAIL_INDEX_FOUND;
		case AS_SINDEX_ERR_INAME_MAXLEN: return AS_PROTO_RESULT_FAIL_INDEX_NAME_MAXLEN;
		case AS_SINDEX_ERR_MAXCOUNT:     return AS_PROTO_RESULT_FAIL_INDEX_MAXCOUNT;
		case AS_SINDEX_ERR_NOTFOUND:     return AS_PROTO_RESULT_FAIL_INDEX_NOTFOUND;
		case AS_SINDEX_ERR_NOT_READABLE: return AS_PROTO_RESULT_FAIL_INDEX_NOTREADABLE;
		case AS_SINDEX_ERR_NO_MEMORY:    return AS_PROTO_RESULT_FAIL_INDEX_OOM;
		case AS_SINDEX_ERR_PARAM:        return AS_PROTO_RESULT_FAIL_PARAMETER;
		case AS_SINDEX_OK:               return AS_PROTO_RESULT_OK;

		// Defensive internal error
		case AS_SINDEX_ERR:
		case AS_SINDEX_ERR_BIN_NOTFOUND:
		case AS_SINDEX_ERR_SET_MISMATCH:
		case AS_SINDEX_ERR_TYPE_MISMATCH:
		case AS_SINDEX_ERR_UNKNOWN_KEYTYPE:
		default: cf_warning(AS_SINDEX, "%s %d Error at %s,%d",
							 as_sindex_err_str(err), err, fname, lineno);
											return AS_PROTO_RESULT_FAIL_INDEX_GENERIC;
	}
}

bool
as_sindex__setname_match(as_sindex_metadata *imd, const char *setname)
{
	// NULL SET being a valid set, logic is a bit complex
	if (setname && ((!imd->set) || strcmp(imd->set, setname))) {
		goto Fail;
	}
	else if (!setname && imd->set) {
		goto Fail;
	}
	return true;
Fail:
	cf_debug(AS_SINDEX, "Index Mismatch %s %s", imd->set, setname);
	return false;
}

/* Returns
 * AS_SINDEX_GC_ERROR if cannot defrag
 * AS_SINDEX_GC_OK if can defrag
 * AS_SINDEX_GC_SKIP_ITERATION if partition lock timed out
 */
as_sindex_gc_status
as_sindex_can_defrag_record(as_namespace *ns, cf_digest *keyd)
{
	as_partition_reservation rsv;
	as_partition_id pid = as_partition_getid(*keyd);

	int timeout_ms = 2;
	if (as_partition_reserve_migrate_timeout(ns, pid, &rsv, 0, timeout_ms) != 0 ) {
		cf_atomic64_incr(&g_stats.sindex_gc_timedout);
		return AS_SINDEX_GC_SKIP_ITERATION;
	}

	int rv = AS_SINDEX_GC_ERROR;
	if (as_record_exists(rsv.tree, keyd, rsv.ns) != 0) {
		rv = AS_SINDEX_GC_OK;
	}
	as_partition_release(&rsv);
	return rv;

}

/*
 * Function as_sindex_pktype
 * 		Returns the type of particle indexed
 *
 * 	Returns -
 * 		On failure - AS_SINDEX_ERR_UNKNOWN_KEYTYPE
 */
as_particle_type
as_sindex_pktype(as_sindex_metadata * imd)
{
	switch(imd->btype) {
		case AS_SINDEX_KTYPE_LONG: {
			return AS_PARTICLE_TYPE_INTEGER;
		}
		case AS_SINDEX_KTYPE_FLOAT: {
			return AS_PARTICLE_TYPE_FLOAT;
		}
		case AS_SINDEX_KTYPE_DIGEST: {
			return AS_PARTICLE_TYPE_STRING;
		}
		case AS_SINDEX_KTYPE_GEO2DSPHERE: {
			return AS_PARTICLE_TYPE_GEOJSON;
		}
		default: {
			cf_warning(AS_SINDEX, "UNKNOWN KEY TYPE FOUND. VERY BAD STATE");
		}
	}
	return AS_SINDEX_ERR_UNKNOWN_KEYTYPE;
}

/*
 * Function as_sindex_key_str
 *     Returns a static string representing the key type
 *
 */
char const *
as_sindex_ktype_str(as_sindex_ktype type)
{
	switch (type) {
	case AS_SINDEX_KTYPE_LONG:      return "NUMERIC";
	case AS_SINDEX_KTYPE_DIGEST:    return "STRING";
	case AS_SINDEX_KTYPE_GEO2DSPHERE:  return "GEOJSON";
	default:
		cf_warning(AS_SINDEX, "UNSUPPORTED KEY TYPE %d", type);
		return "??????";
	}
}

as_sindex_ktype
as_sindex_ktype_from_string(char const * type_str)
{
	if (!type_str) {
		cf_warning(AS_SINDEX, "missing secondary index key type");
		return AS_SINDEX_KTYPE_NONE;
	}
	else if (strncasecmp(type_str, "string", 6) == 0) {
		return AS_SINDEX_KTYPE_DIGEST;
	}
	else if (strncasecmp(type_str, "numeric", 7) == 0) {
		return AS_SINDEX_KTYPE_LONG;
	}
	else if (strncasecmp(type_str, "geo2dsphere", 11) == 0) {
		return AS_SINDEX_KTYPE_GEO2DSPHERE;
	}
	else {
		cf_warning(AS_SINDEX, "UNRECOGNIZED KEY TYPE %s", type_str);
		return AS_SINDEX_KTYPE_NONE;
	}
}

as_sindex_key_type
as_sindex_key_type_from_pktype(as_particle_type t)
{
	switch(t) {
		case AS_PARTICLE_TYPE_INTEGER :     return AS_SINDEX_KEY_TYPE_LONG;
		case AS_PARTICLE_TYPE_STRING  :     return AS_SINDEX_KEY_TYPE_DIGEST;
		case AS_PARTICLE_TYPE_GEOJSON :     return AS_SINDEX_KEY_TYPE_GEO2DSPHERE;
		default                       :     {
			cf_warning(AS_SINDEX, "bad particle type %d", t);
			return AS_SINDEX_KEY_TYPE_MAX;
		}
	}
	return AS_SINDEX_KEY_TYPE_MAX;
}

as_sindex_ktype
as_sindex_sktype_from_pktype(as_particle_type t)
{
	switch(t) {
		case AS_PARTICLE_TYPE_INTEGER :     return AS_SINDEX_KTYPE_LONG;
		case AS_PARTICLE_TYPE_FLOAT   :     return AS_SINDEX_KTYPE_FLOAT;
		case AS_PARTICLE_TYPE_STRING  :     return AS_SINDEX_KTYPE_DIGEST;
		case AS_PARTICLE_TYPE_GEOJSON :     return AS_SINDEX_KTYPE_GEO2DSPHERE;
		default                       :     return AS_SINDEX_KTYPE_NONE;
	}
	return AS_SINDEX_KTYPE_NONE;
}

// Always make this function get cfg default from as_sindex structure's values,
// instead of hard-coding it : useful when the defaults change.
// This also gets called during config-file init, at that time, we are using a
// dummy variable init.
void
as_sindex_config_var_default(as_sindex_config_var *si_cfg)
{
	// Mandatory memset, Totally worth the cost
	// Do not remove
	memset(si_cfg, 0, sizeof(as_sindex_config_var));

	as_sindex from_si;
	as_sindex__config_default(&from_si);

	// 2 of the 6 variables : enable-histogram and trace-flag are not a part of default-settings for si
	si_cfg->defrag_period        = from_si.config.defrag_period;
	si_cfg->defrag_max_units     = from_si.config.defrag_max_units;
	// related non config value defaults
	si_cfg->data_max_memory      = from_si.config.data_max_memory;
	si_cfg->ignore_not_sync_flag = from_si.config.flag;
}

/*
 * Client API to check if there is secondary index on given namespace
 */
int
as_sindex_ns_has_sindex(as_namespace *ns)
{
	return (ns->sindex_cnt > 0);
}

char *as_sindex_type_defs[] =
{	"NONE", "LIST", "MAPKEYS", "MAPVALUES"
};

/*
 * Returns -
 * 		AS_SINDEX_OK  - On success.
 *		Else on failure one of these -
 * 			AS_SINDEX_ERR
 * 			AS_SINDEX_ERR_OTHER
 * 			AS_SINDEX_ERR_NOT_READABLE
 * Notes -
 * 		Assert anything which is inconsistent with the way DML/DML/DDL/defrag_th/destroy_th
 * 		running in multi-threaded environment.
 * 		This is called before acquiring secondary index lock.
 *
 * Synchronization -
 * 		reserves the imd.
 * 		Caller of DML should always reserves si.
 */
int
as_sindex__pre_op_assert(as_sindex *si, int op)
{
	int ret = AS_SINDEX_ERR;
	if (!si) {
		SINDEX_CRASH("DML with NULL si"); return ret;
	}
	if (!si->imd) {
		SINDEX_CRASH("DML with NULL imd"); return ret;
	}

	// Caller of DML should always reserves si, If the state of si is not DESTROY and
	// if the count is 1 then caller did not reserve fail the assertion
	int count = cf_rc_count(si->imd);
	cf_debug(AS_SINDEX, "DML on index %s in %d state with reference count %d < 2", si->imd->iname, si->state, count);
	if ((count < 2) && (si->state != AS_SINDEX_DESTROY)) {
		cf_warning(AS_SINDEX, "Secondary index is improperly ref counted ... cannot be used");
		return ret;
	}
	ret = AS_SINDEX_OK;

	switch (op)
	{
		case AS_SINDEX_OP_READ:
			// First one signifies that index is still getting built
			// Second on signifies because of some failure secondary
			// is not in sync with primary
			if (!(si->flag & AS_SINDEX_FLAG_RACTIVE)
				|| ( (si->desync_cnt > 0)
					&& !(si->config.flag & AS_SINDEX_CONFIG_IGNORE_ON_DESYNC))) {
				ret = AS_SINDEX_ERR_NOT_READABLE;
			}
			break;
		case AS_SINDEX_OP_INSERT:
		case AS_SINDEX_OP_DELETE:
			break;
		default:
			cf_warning(AS_SINDEX, "Unidentified Secondary Index Op .. Ignoring!!");
	}
	return ret;
}

/*
 * Create duplicate copy of sindex metadata. New lock is created
 * used by index create by user at runtime or index creation at the boot time
 */
void
as_sindex__dup_meta(as_sindex_metadata *imd, as_sindex_metadata **qimd,
		bool refcounted)
{
	if (!imd) return;
	as_sindex_metadata *qimdp;

	if (refcounted) qimdp = cf_rc_alloc(sizeof(as_sindex_metadata));
	else            qimdp = cf_malloc(  sizeof(as_sindex_metadata));
	memset(qimdp, 0, sizeof(as_sindex_metadata));

	qimdp->ns_name = cf_strdup(imd->ns_name);

	// Set name is optional for create
	if (imd->set) {
		qimdp->set = cf_strdup(imd->set);
	} else {
		qimdp->set = NULL;
	}

	qimdp->iname       = cf_strdup(imd->iname);
	qimdp->itype       = imd->itype;
	qimdp->nprts       = imd->nprts;
	qimdp->path_str    = cf_strdup(imd->path_str);
	qimdp->path_length = imd->path_length;
	memcpy(qimdp->path, imd->path, AS_SINDEX_MAX_DEPTH*sizeof(as_sindex_path));
	qimdp->bname       = cf_strdup(imd->bname);
	qimdp->btype       = imd->btype;
	qimdp->binid       = imd->binid;


	pthread_rwlockattr_t rwattr;
	if (pthread_rwlockattr_init(&rwattr))
		cf_crash(AS_AS,  "pthread_rwlockattr_init: %s",
					cf_strerror(errno));
	if (pthread_rwlockattr_setkind_np(&rwattr,
				PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)) {
		cf_crash( AS_TSVC, "pthread_rwlockattr_setkind_np: %s",
				cf_strerror(errno));
	}
	if (pthread_rwlock_init(&qimdp->slock, &rwattr)) {
		cf_crash(AS_SINDEX,
				"Could not create secondary index dml mutex ");
	}
	qimdp->flag |= IMD_FLAG_LOCKSET;

	*qimd = qimdp;
}

/*
 * Function to perform validation check on the return type and increment
 * decrement all the statistics.
 */
void
as_sindex__process_ret(as_sindex *si, int ret, as_sindex_op op,
		uint64_t starttime, int pos)
{
	switch(op) {
		case AS_SINDEX_OP_INSERT:
			if (AS_SINDEX_ERR_NO_MEMORY == ret) {
				cf_atomic_int_incr(&si->desync_cnt);
			}
			if (ret && ret != AS_SINDEX_KEY_FOUND) {
				cf_debug(AS_SINDEX,
						"SINDEX_FAIL: Insert into %s failed at %d with %d",
						si->imd->iname, pos, ret);
				cf_atomic64_incr(&si->stats.write_errs);
			} else if (!ret) {
				cf_atomic64_incr(&si->stats.n_objects);
			}
			cf_atomic64_incr(&si->stats.n_writes);
			SINDEX_HIST_INSERT_DATA_POINT(si, write_hist, starttime);
			break;
		case AS_SINDEX_OP_DELETE:
			if (ret && ret != AS_SINDEX_KEY_NOTFOUND) {
				cf_debug(AS_SINDEX,
						"SINDEX_FAIL: Delete from %s failed at %d with %d",
	                    si->imd->iname, pos, ret);
				cf_atomic64_incr(&si->stats.delete_errs);
			} else if (!ret) {
				cf_atomic64_decr(&si->stats.n_objects);
			}
			cf_atomic64_incr(&si->stats.n_deletes);
			SINDEX_HIST_INSERT_DATA_POINT(si, delete_hist, starttime);
			break;
		case AS_SINDEX_OP_READ:
			if (ret < 0) { // AS_SINDEX_CONTINUE(1) also OK
				cf_debug(AS_SINDEX,
						"SINDEX_FAIL: Read from %s failed at %d with %d",
						si->imd->iname, pos, ret);
				cf_atomic64_incr(&si->stats.read_errs);
			}
			cf_atomic64_incr(&si->stats.n_reads);
			break;
		default:
			cf_crash(AS_SINDEX, "Invalid op");
	}
}

// Bin id should be around
// if not create it
// TODO is it not needed
int
as_sindex__populate_binid(as_namespace *ns, as_sindex_metadata *imd)
{
	int len  = strlen(imd->bname);
	if (len >= AS_ID_BIN_SZ) {
		cf_warning(AS_SINDEX, "bin name %s of size %d too big. Max size allowed is %d",
							imd->bname, len, AS_ID_BIN_SZ-1);
		return AS_SINDEX_ERR;
	}

	if(!as_bin_name_within_quota(ns, imd->bname)) {
		cf_warning(AS_SINDEX, "Bin %s not added. Quota is full", imd->bname);
		return AS_SINDEX_ERR;
	}

	// An extra strncpy to remove valgrind warning
	char bname[AS_ID_BIN_SZ];
	strncpy(bname, imd->bname, AS_ID_BIN_SZ);
	imd->binid = as_bin_get_or_assign_id(ns, bname);
	cf_debug(AS_SINDEX, " Assigned %d for %s", imd->binid, imd->bname);

	return AS_SINDEX_OK;
}

// Free if IMD has allocated the info in it
int
as_sindex_imd_free(as_sindex_metadata *imd)
{
	if (!imd) {
		cf_warning(AS_SINDEX, "imd is null in as_sindex_imd_free");
		return AS_SINDEX_ERR;
	}

	if (imd->ns_name) {
		cf_free(imd->ns_name);
		imd->ns_name = NULL;
	}

	if (imd->iname) {
		cf_free(imd->iname);
		imd->iname = NULL;
	}

	if (imd->set) {
		cf_free(imd->set);
		imd->set = NULL;
	}

	if (imd->path_str) {
		cf_free(imd->path_str);
		imd->path_str = NULL;
	}

	if (imd->flag & IMD_FLAG_LOCKSET) {
		pthread_rwlock_destroy(&imd->slock);
	}

	if (imd->bname) {
		cf_free(imd->bname);
		imd->bname = NULL;
	}

	return AS_SINDEX_OK;
}
//                                           END - UTILITY
// ************************************************************************************************
// ************************************************************************************************
//                                           METADATA
typedef struct sindex_set_binid_hash_ele_s {
	cf_ll_element ele;
	int           simatch;
} sindex_set_binid_hash_ele;

void
as_sindex__set_binid_hash_destroy(cf_ll_element * ele) {
	cf_free((sindex_set_binid_hash_ele * ) ele);
}

/*
 * Should happen under SINDEX_GWLOCK
 */
as_sindex_status
as_sindex__put_in_set_binid_hash(as_namespace * ns, char * set, int binid, int chosen_id)
{
	// Create fixed size key for hash
	// Get the linked list from the hash
	// If linked list does not exist then make one and put it in the hash
	// Append the chosen id in the linked list

	if (chosen_id < 0 || chosen_id > AS_SINDEX_MAX) {
		cf_debug(AS_SINDEX, "Put in set_binid hash got invalid simatch %d", chosen_id);
		return AS_SINDEX_ERR;
	}
	cf_ll * simatch_ll = NULL;
	// Create fixed size key for hash
	char si_prop[AS_SINDEX_PROP_KEY_SIZE];
	memset(si_prop, 0, AS_SINDEX_PROP_KEY_SIZE);

	if (set == NULL ) {
		sprintf(si_prop, "_%d", binid);
	}
	else {
		sprintf(si_prop, "%s_%d", set, binid);
	}

	// Get the linked list from the hash
	int rv      = shash_get(ns->sindex_set_binid_hash, (void *)si_prop, (void *)&simatch_ll);

	// If linked list does not exist then make one and put it in the hash
	if (rv && rv != SHASH_ERR_NOTFOUND) {
		cf_debug(AS_SINDEX, "shash get failed with error %d", rv);
		return AS_SINDEX_ERR;
	};
	if (rv == SHASH_ERR_NOTFOUND) {
		simatch_ll = cf_malloc(sizeof(cf_ll));
		cf_ll_init(simatch_ll, as_sindex__set_binid_hash_destroy, false);
		if (SHASH_OK != shash_put(ns->sindex_set_binid_hash, (void *)si_prop, (void *)&simatch_ll)) {
			cf_warning(AS_SINDEX, "shash put failed for key %s", si_prop);
			return AS_SINDEX_ERR;
		}
	}
	if (!simatch_ll) {
		return AS_SINDEX_ERR;
	}

	// Append the chosen id in the linked list
	sindex_set_binid_hash_ele * ele = cf_malloc(sizeof(sindex_set_binid_hash_ele));
	ele->simatch                    = chosen_id;
	cf_ll_append(simatch_ll, (cf_ll_element*)ele);
	return AS_SINDEX_OK;
}

/*
 * Should happen under SINDEX_GWLOCK
 */
as_sindex_status
as_sindex__delete_from_set_binid_hash(as_namespace * ns, as_sindex_metadata * imd)
{
	// Make a key
	// Get the sindex list corresponding to key
	// If the list does not exist, return does not exist
	// If the list exist
	// 		match the path and type of incoming si to the existing sindexes in the list
	// 		If any element matches
	// 			Delete from the list
	// 			If the list size becomes 0
	// 				Delete the entry from the hash
	// 		If none of the element matches, return does not exist.
	//

	// Make a key
	char si_prop[AS_SINDEX_PROP_KEY_SIZE];
	memset(si_prop, 0, AS_SINDEX_PROP_KEY_SIZE);
	if (imd->set == NULL ) {
		sprintf(si_prop, "_%d", imd->binid);
	}
	else {
		sprintf(si_prop, "%s_%d", imd->set, imd->binid);
	}

	// Get the sindex list corresponding to key
	cf_ll * simatch_ll = NULL;
	int rv             = shash_get(ns->sindex_set_binid_hash, (void *)si_prop, (void *)&simatch_ll);

	// If the list does not exist, return does not exist
	if (rv && rv != SHASH_ERR_NOTFOUND) {
		cf_debug(AS_SINDEX, "shash get failed with error %d", rv);
		return AS_SINDEX_ERR_NOTFOUND;
	};
	if (rv == SHASH_ERR_NOTFOUND) {
		return AS_SINDEX_ERR_NOTFOUND;
	}

	// If the list exist
	// 		match the path and type of incoming si to the existing sindexes in the list
	bool    to_delete                    = false;
	cf_ll_element * ele                  = NULL;
	sindex_set_binid_hash_ele * prop_ele = NULL;
	if (simatch_ll) {
		ele = cf_ll_get_head(simatch_ll);
		while (ele) {
			prop_ele       = ( sindex_set_binid_hash_ele * ) ele;
			as_sindex * si = &(ns->sindex[prop_ele->simatch]);
			if (strcmp(si->imd->path_str, imd->path_str) == 0 &&
				si->imd->btype == imd->btype && si->imd->itype == imd->itype) {
				to_delete  = true;
				break;
			}
			ele = ele->next;
		}
	}
	else {
		return AS_SINDEX_ERR_NOTFOUND;
	}

	// 		If any element matches
	// 			Delete from the list
	if (to_delete && ele) {
		cf_ll_delete(simatch_ll, ele);
	}

	// 			If the list size becomes 0
	// 				Delete the entry from the hash
	if (cf_ll_size(simatch_ll) == 0) {
		rv = shash_delete(ns->sindex_set_binid_hash, si_prop);
		if (rv) {
			cf_debug(AS_SINDEX, "shash_delete fails with error %d", rv);
		}
	}

	// 		If none of the element matches, return does not exist.
	if (!to_delete) {
		return AS_SINDEX_ERR_NOTFOUND;
	}
	return AS_SINDEX_OK;
}

// Hash a binname string.
static inline uint32_t
as_sindex__set_binid_hash_fn(void* p_key)
{
	return (uint32_t)cf_hash_fnv(p_key, sizeof(uint32_t));
}

// Hash a binname string.
static inline uint32_t
as_sindex__iname_hash_fn(void* p_key)
{
	return (uint32_t)cf_hash_fnv(p_key, strlen((const char*)p_key));
}


//                                         END - METADATA
// ************************************************************************************************
// ************************************************************************************************
//                                             LOOKUP
/*
 * Should happen under SINDEX_GRLOCK if called directly.
 */
as_sindex_status
as_sindex__simatch_list_by_set_binid(as_namespace * ns, const char *set, int binid, cf_ll ** simatch_ll)
{
	// Make the fixed size key (set_binid)
	// Look for the key in set_binid_hash
	// If found return the value (list of simatches)
	// Else return NULL

	// Make the fixed size key (set_binid)
	char si_prop[AS_SINDEX_PROP_KEY_SIZE];
	memset(si_prop, 0, AS_SINDEX_PROP_KEY_SIZE);
	if (!set) {
		sprintf(si_prop, "_%d", binid);
	}
	else {
		sprintf(si_prop, "%s_%d", set, binid);
	}

	// Look for the key in set_binid_hash
	int rv             = shash_get(ns->sindex_set_binid_hash, (void *)si_prop, (void *)simatch_ll);

	// If not found return NULL
	if (rv || !(*simatch_ll)) {
		cf_debug(AS_SINDEX, "shash get failed with error %d", rv);
		return AS_SINDEX_ERR_NOTFOUND;
	};

	// Else return simatch_ll
	return AS_SINDEX_OK;
}

/*
 * Should happen under SINDEX_GRLOCK
 */
int
as_sindex__simatch_by_set_binid(as_namespace *ns, char * set, int binid, as_sindex_ktype type, as_sindex_type itype, char * path)
{
	// get the list corresponding to the list from the hash
	// if list does not exist return -1
	// If list exist
	// 		Iterate through all the elements in the list and match the path and type
	// 		If matches
	// 			return the simatch
	// 	If none of the si matches
	// 		return -1

	cf_ll * simatch_ll = NULL;
	as_sindex__simatch_list_by_set_binid(ns, set, binid, &simatch_ll);

	// If list exist
	// 		Iterate through all the elements in the list and match the path and type
	int     simatch                      = -1;
	sindex_set_binid_hash_ele * prop_ele = NULL;
	cf_ll_element * ele                  = NULL;
	if (simatch_ll) {
		ele = cf_ll_get_head(simatch_ll);
		while (ele) {
			prop_ele = ( sindex_set_binid_hash_ele * ) ele;
			as_sindex * si = &(ns->sindex[prop_ele->simatch]);
			if (strcmp(si->imd->path_str, path) == 0 &&
				si->imd->btype == type && si->imd->itype == itype) {
				simatch  = prop_ele->simatch;
				break;
			}
			ele = ele->next;
		}
	}
	else {
		return -1;
	}

	// 		If matches
	// 			return the simatch
	// 	If none of the si matches
	// 		return -1
	return simatch;
}

// Populates the si_arr with all the sindexes which matches set and binid
// Each sindex is reserved as well. Enough space is provided by caller in si_arr
// Currently only 8 sindexes can be create on one combination of set and binid
// i.e number_of_sindex_types * number_of_sindex_data_type (4 * 2)
int
as_sindex_arr_lookup_by_set_binid_lockfree(as_namespace * ns, const char *set, int binid, as_sindex ** si_arr)
{
	cf_ll * simatch_ll=NULL;

	int sindex_count = 0;
	if (!as_sindex_binid_has_sindex(ns, binid) ) {
		return sindex_count;
	}

	as_sindex__simatch_list_by_set_binid(ns, set, binid, &simatch_ll);
	if (!simatch_ll) {
		return sindex_count;
	}

	cf_ll_element             * ele    = cf_ll_get_head(simatch_ll);
	sindex_set_binid_hash_ele * si_ele = NULL;
	int                        simatch = -1;
	as_sindex                 * si     = NULL;
	while (ele) {
		si_ele                         = (sindex_set_binid_hash_ele *) ele;
		simatch                        = si_ele->simatch;

		if (simatch == -1) {
			cf_warning(AS_SINDEX, "A matching simatch comes out to be -1.");
			ele = ele->next;
			continue;
		}

		si                             = &ns->sindex[simatch];
		// Reserve only active sindexes.
		// Do not break this rule
		if (!as_sindex_isactive(si)) {
			ele = ele->next;
			continue;
		}

		if (simatch != si->simatch) {
			cf_warning(AS_SINDEX, "Inconsistent simatch reference between simatch stored in"
									"si and simatch stored in hash");
			ele = ele->next;
			continue;
		}

		AS_SINDEX_RESERVE(si);

		si_arr[sindex_count++] = si;
		ele = ele->next;
	}
	return sindex_count;
}

// Populates the si_arr with all the sindexes which matches setname
// Each sindex is reserved as well. Enough space is provided by caller in si_arr
int
as_sindex_arr_lookup_by_setname_lockfree(as_namespace * ns, const char *setname, as_sindex ** si_arr)
{
	int sindex_count = 0;
	as_sindex * si = NULL;

	for (int i=0; i<AS_SINDEX_MAX; i++) {
		if (sindex_count >= ns->sindex_cnt) {
			break;
		}
		si = &ns->sindex[i];
		// Reserve only active sindexes.
		// Do not break this rule
		if (!as_sindex_isactive(si)) {
			continue;
		}
	
		SINDEX_RLOCK(&si->imd->slock);
		if (!as_sindex__setname_match(si->imd, setname)) {
			SINDEX_UNLOCK(&si->imd->slock);
			continue;
		}
		SINDEX_UNLOCK(&si->imd->slock);
	
		AS_SINDEX_RESERVE(si);

		si_arr[sindex_count++] = si;
	}

	return sindex_count;
}
int
as_sindex__simatch_by_iname(as_namespace *ns, char *idx_name)
{
	int simatch = -1;
	char iname[AS_ID_INAME_SZ]; memset(iname, 0, AS_ID_INAME_SZ);
	snprintf(iname, strlen(idx_name) + 1, "%s", idx_name);
	int rv      = shash_get(ns->sindex_iname_hash, (void *)iname, (void *)&simatch);
	cf_detail(AS_SINDEX, "Found iname simatch %s->%d rv=%d", iname, simatch, rv);

	if (rv) {
		return -1;
	}
	return simatch;
}
/*
 * Single cluttered interface for lookup. iname precedes binid
 * i.e if both are specified search is done with iname
 */
#define AS_SINDEX_LOOKUP_FLAG_SETCHECK     0x01
#define AS_SINDEX_LOOKUP_FLAG_ISACTIVE     0x02
#define AS_SINDEX_LOOKUP_FLAG_NORESERVE    0x04
as_sindex *
as_sindex__lookup_lockfree(as_namespace *ns, char *iname, char *set, int binid,
								as_sindex_ktype type, as_sindex_type itype, char * path, char flag)
{

	// If iname is not null then search in iname hash and store the simatch
	// Else then
	// 		Check the possible existence of sindex over bin in the bit array
	//		If no possibility return NULL
	//		Search in the set_binid hash using setname, binid, itype and binid
	//		If found store simatch
	//		If not found return NULL
	//			Get the sindex corresponding to the simatch.
	// 			Apply the flags applied by caller.
	//          Validate the simatch

	int simatch   = -1;
	as_sindex *si = NULL;
	// If iname is not null then search in iname hash and store the simatch
	if (iname) {
		simatch   = as_sindex__simatch_by_iname(ns, iname);
	}
	// Else then
	// 		Check the possible existence of sindex over bin in the bit array
	else {
		if (!as_sindex_binid_has_sindex(ns,  binid) ) {
	//		If no possibility return NULL
			goto END;
		}
	//		Search in the set_binid hash using setname, binid, itype and binid
	//		If found store simatch
		simatch   = as_sindex__simatch_by_set_binid(ns, set, binid, type, itype, path);
	}
	//		If not found return NULL
	// 			Get the sindex corresponding to the simatch.
	if (simatch != -1) {
		si      = &ns->sindex[simatch];
	// 			Apply the flags applied by caller.
		if ((flag & AS_SINDEX_LOOKUP_FLAG_ISACTIVE)
			&& !as_sindex_isactive(si)) {
			si = NULL;
			goto END;
		}
	//          Validate the simatch
		if (simatch != si->simatch) {
			cf_warning(AS_SINDEX, "Inconsistent simatch reference between simatch stored in"
									"si and simatch stored in hash");
		}
		if (!(flag & AS_SINDEX_LOOKUP_FLAG_NORESERVE))
			AS_SINDEX_RESERVE(si);
	}
END:
	return si;
}

as_sindex *
as_sindex__lookup(as_namespace *ns, char *iname, char *set, int binid, as_sindex_ktype type,
						as_sindex_type itype, char * path, char flag)
{
	SINDEX_GRLOCK();
	as_sindex *si = as_sindex__lookup_lockfree(ns, iname, set, binid, type, itype, path, flag);
	SINDEX_GUNLOCK();
	return si;
}

as_sindex *
as_sindex_lookup_by_iname(as_namespace *ns, char * iname, char flag)
{
	return as_sindex__lookup(ns, iname, NULL, -1, 0, 0, NULL, flag);
}

as_sindex *
as_sindex_lookup_by_defns(as_namespace *ns, char *set, int binid, as_sindex_ktype type, as_sindex_type itype, char * path, char flag)
{
	return as_sindex__lookup(ns, NULL, set, binid, type, itype, path, flag);
}

as_sindex *
as_sindex_lookup_by_iname_lockfree(as_namespace *ns, char * iname, char flag)
{
	return as_sindex__lookup_lockfree(ns, iname, NULL, -1, 0, 0, NULL, flag);

}

as_sindex *
as_sindex_lookup_by_defns_lockfree(as_namespace *ns, char *set, int binid, as_sindex_ktype type, as_sindex_type itype, char * path, char flag)
{
	return as_sindex__lookup_lockfree(ns, NULL, set, binid, type, itype, path, flag);
}

/*
 * Description     : Checks whether an index with the same defn already exists.
 *                   Index defn ={index_name, bin_name, bintype, set_name, ns_name}
 *
 * Parameters      : ns  -> namespace in which index is created
 *                   imd -> imd for create request (does not have binid populated)
 *
 * Returns         : true  if index with the given defn already exists.
 *                   false otherwise
 *
 * Synchronization : Required lock acquired by lookup functions.
 */
bool
as_sindex_exists_by_defn(as_namespace* ns, as_sindex_metadata* imd)
{
	char *iname    = imd->iname;
	// This will reserve the si
	as_sindex * si = as_sindex_lookup_by_iname(ns, iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if(!si) {
		return false;
	}
	int binid     = as_bin_get_id(ns, imd->bname);
	if(si->imd->bname && imd->bname) {
		if (binid == si->imd->binid && !strcmp(imd->bname, si->imd->bname)
						&& imd->btype == si->imd->btype) {
			AS_SINDEX_RELEASE(si);
			return true;
		}
	}

	AS_SINDEX_RELEASE(si);
	return false;
}
//                                           END LOOKUP
// ************************************************************************************************
// ************************************************************************************************
//                                          STAT/CONFIG/HISTOGRAM
void
as_sindex__stats_clear(as_sindex *si) {
	as_sindex_stat *s = &si->stats;

	s->n_objects            = 0;

	s->n_reads              = 0;
	s->read_errs            = 0;

	s->n_writes             = 0;
	s->write_errs           = 0;

	s->n_deletes            = 0;
	s->delete_errs          = 0;

	s->loadtime             = 0;
	s->recs_pending         = 0;

	s->n_defrag_records     = 0;
	s->defrag_time          = 0;

	// Aggregation stat
	s->n_aggregation        = 0;
	s->agg_response_size    = 0;
	s->agg_num_records      = 0;
	s->agg_errs             = 0;
	// Lookup stats
	s->n_lookup             = 0;
	s->lookup_response_size = 0;
	s->lookup_num_records   = 0;
	s->lookup_errs          = 0;

	si->enable_histogram = false;
	if (s->_write_hist) {
		histogram_clear(s->_write_hist);
	}
	if (s->_si_prep_hist) {
		histogram_clear(s->_si_prep_hist);
	}
	if (s->_delete_hist) {
		histogram_clear(s->_delete_hist);
	}
	if (s->_query_hist) {
		histogram_clear(s->_query_hist);
	}
	if (s->_query_batch_io) {
		histogram_clear(s->_query_batch_io);
	}
	if (s->_query_batch_lookup) {
		histogram_clear(s->_query_batch_lookup);
	}
	if (s->_query_rcnt_hist) {
		histogram_clear(s->_query_rcnt_hist);
	}
	if (s->_query_diff_hist) {
		histogram_clear(s->_query_diff_hist);
	}
}

void
as_sindex_gconfig_default(as_config *c)
{
	c->sindex_builder_threads         = 4;
	c->sindex_data_max_memory         = ULONG_MAX;
	c->sindex_data_memory_used        = 0;
}
void
as_sindex__config_default(as_sindex *si)
{
	si->config.defrag_period    = 1000;
	si->config.defrag_max_units = 1000;
	si->config.data_max_memory  = ULONG_MAX; // No Limit
	si->config.flag             = 1; // Default is - index is active
}

void
as_sindex_config_var_copy(as_sindex *to_si, as_sindex_config_var *from_si_cfg)
{
	to_si->config.defrag_period    = from_si_cfg->defrag_period;
	to_si->config.defrag_max_units = from_si_cfg->defrag_max_units;
	to_si->config.data_max_memory  = from_si_cfg->data_max_memory;
	to_si->enable_histogram        = from_si_cfg->enable_histogram;
	to_si->config.flag             = from_si_cfg->ignore_not_sync_flag;
}
void
as_sindex__setup_histogram(as_sindex *si)
{
	char hist_name[AS_ID_INAME_SZ+64];
	sprintf(hist_name, "%s_write_us", si->imd->iname);
	if (NULL == (si->stats._write_hist = histogram_create(hist_name, HIST_MICROSECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex write histogram");

	sprintf(hist_name, "%s_si_prep_us", si->imd->iname);
	if (NULL == (si->stats._si_prep_hist = histogram_create(hist_name, HIST_MICROSECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex prepare histogram");

	sprintf(hist_name, "%s_delete_us", si->imd->iname);
	if (NULL == (si->stats._delete_hist = histogram_create(hist_name, HIST_MICROSECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex delete histogram");

	sprintf(hist_name, "%s_query", si->imd->iname);
	if (NULL == (si->stats._query_hist = histogram_create(hist_name, HIST_MILLISECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex query histogram");

	sprintf(hist_name, "%s_query_batch_lookup_us", si->imd->iname);
	if (NULL == (si->stats._query_batch_lookup = histogram_create(hist_name, HIST_MICROSECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex query batch-lookup histogram");

	sprintf(hist_name, "%s_query_batch_io_us", si->imd->iname);
	if (NULL == (si->stats._query_batch_io = histogram_create(hist_name, HIST_MICROSECONDS)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex query io histogram");

	sprintf(hist_name, "%s_query_row_count", si->imd->iname);
	if (NULL == (si->stats._query_rcnt_hist = histogram_create(hist_name, HIST_RAW)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex query row count histogram");

	sprintf(hist_name, "%s_query_diff_count", si->imd->iname);
	if (NULL == (si->stats._query_diff_hist = histogram_create(hist_name, HIST_RAW)))
		cf_warning(AS_SINDEX, "couldn't create histogram for sindex query diff histogram");

}

int
as_sindex__destroy_histogram(as_sindex *si)
{
	if (si->stats._write_hist)            cf_free(si->stats._write_hist);
	if (si->stats._si_prep_hist)          cf_free(si->stats._si_prep_hist);
	if (si->stats._delete_hist)           cf_free(si->stats._delete_hist);
	if (si->stats._query_hist)            cf_free(si->stats._query_hist);
	if (si->stats._query_batch_lookup)    cf_free(si->stats._query_batch_lookup);
	if (si->stats._query_batch_io)        cf_free(si->stats._query_batch_io);
	if (si->stats._query_rcnt_hist)       cf_free(si->stats._query_rcnt_hist);
	if (si->stats._query_diff_hist)       cf_free(si->stats._query_diff_hist);
	return 0;
}

int
as_sindex_stats_str(as_namespace *ns, char * iname, cf_dyn_buf *db)
{
	as_sindex *si = as_sindex_lookup_by_iname(ns, iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);

	if (!si) {
		cf_warning(AS_SINDEX, "SINDEX STAT : sindex %s not found", iname);
		return AS_SINDEX_ERR_NOTFOUND;
	}

	// A good thing to cache the stats first.
	int      ns_objects  = ns->n_objects;
	uint64_t si_objects  = cf_atomic64_get(si->stats.n_objects);
	uint64_t pending     = cf_atomic64_get(si->stats.recs_pending);
	uint64_t si_memory   = cf_atomic64_get(si->stats.mem_used);
	// To protect the pimd while accessing it.
	SINDEX_RLOCK(&si->imd->slock);
	uint64_t n_keys      = ai_btree_get_numkeys(si->imd);
	SINDEX_UNLOCK(&si->imd->slock);
	info_append_uint64(db, "keys", n_keys);
	info_append_uint64(db, "entries", si_objects);
	SINDEX_RLOCK(&si->imd->slock);
	uint64_t i_size      = ai_btree_get_isize(si->imd);
	uint64_t n_size      = ai_btree_get_nsize(si->imd);
	SINDEX_UNLOCK(&si->imd->slock);
	info_append_uint64(db, "ibtr_memory_used", i_size);
	info_append_uint64(db, "nbtr_memory_used", n_size);
	info_append_uint64(db, "si_accounted_memory", si_memory);
	if (si->flag & AS_SINDEX_FLAG_RACTIVE) {
		info_append_string(db, "load_pct", "100");
	} else {
		if (pending > ns_objects || pending < 0) {
			info_append_uint64(db, "load_pct", 100);
		} else {
			info_append_uint64(db, "load_pct", (ns_objects == 0) ? 100 : 100 - ((100 * pending) / ns_objects));
		}
	}

	info_append_uint64(db, "loadtime", cf_atomic64_get(si->stats.loadtime));
	// writes
	info_append_uint64(db, "write_success", cf_atomic64_get(si->stats.n_writes) - cf_atomic64_get(si->stats.write_errs));
	info_append_uint64(db, "write_error", cf_atomic64_get(si->stats.write_errs));
	// delete
	info_append_uint64(db, "delete_success", cf_atomic64_get(si->stats.n_deletes) - cf_atomic64_get(si->stats.delete_errs));
	info_append_uint64(db, "delete_error", cf_atomic64_get(si->stats.delete_errs));
	// defrag
	info_append_uint64(db, "stat_gc_recs", cf_atomic64_get(si->stats.n_defrag_records));
	info_append_uint64(db, "stat_gc_time", cf_atomic64_get(si->stats.defrag_time));

	// Cache values
	uint64_t agg        = cf_atomic64_get(si->stats.n_aggregation);
	uint64_t agg_rec    = cf_atomic64_get(si->stats.agg_num_records);
	uint64_t agg_size   = cf_atomic64_get(si->stats.agg_response_size);
	uint64_t lkup       = cf_atomic64_get(si->stats.n_lookup);
	uint64_t lkup_rec   = cf_atomic64_get(si->stats.lookup_num_records);
	uint64_t lkup_size  = cf_atomic64_get(si->stats.lookup_response_size);
	uint64_t query      = agg      + lkup;
	uint64_t query_rec  = agg_rec  + lkup_rec;
	uint64_t query_size = agg_size + lkup_size;

	// Query
	info_append_uint64(db, "query_reqs", query);
	info_append_uint64(db, "query_avg_rec_count", query ? query_rec / query : 0);
	info_append_uint64(db, "query_avg_record_size", query_rec ? query_size / query_rec : 0);
	// Aggregation
	info_append_uint64(db, "query_agg", agg);
	info_append_uint64(db, "query_agg_avg_rec_count", agg ? agg_rec / agg : 0);
	info_append_uint64(db, "query_agg_avg_record_size", agg_rec ? agg_size / agg_rec : 0);
	//Lookup
	info_append_uint64(db, "query_lookups", lkup);
	info_append_uint64(db, "query_lookup_avg_rec_count", lkup ? lkup_rec / lkup : 0);
	info_append_uint64(db, "query_lookup_avg_record_size", lkup_rec ? lkup_size / lkup_rec : 0);

	//CONFIG
	info_append_uint64(db, "gc-period", si->config.defrag_period);
	info_append_uint32(db, "gc-max-units", si->config.defrag_max_units);
	if (si->config.data_max_memory != ULONG_MAX) {
		info_append_uint64(db, "data-max-memory", si->config.data_max_memory);
	} else {
		info_append_string(db, "data-max-memory", "ULONG_MAX");
	}

	info_append_bool(db, "histogram", si->enable_histogram);
	info_append_bool(db, "ignore-not-sync", (si->config.flag & AS_SINDEX_CONFIG_IGNORE_ON_DESYNC) != 0);

	cf_dyn_buf_chomp(db);

	AS_SINDEX_RELEASE(si);
	// Release reference
	return AS_SINDEX_OK;
}

int
as_sindex_histogram_dumpall(as_namespace *ns)
{
	if (!ns)
		return AS_SINDEX_ERR_PARAM;
	SINDEX_GRLOCK();

	for (int i = 0; i < ns->sindex_cnt; i++) {
		if (ns->sindex[i].state != AS_SINDEX_ACTIVE) continue;
		if (!ns->sindex[i].enable_histogram)         continue;
		as_sindex *si = &ns->sindex[i];
		if (si->stats._write_hist)
			histogram_dump(si->stats._write_hist);
		if (si->stats._si_prep_hist)
			histogram_dump(si->stats._si_prep_hist);
		if (si->stats._delete_hist)
			histogram_dump(si->stats._delete_hist);
		if (si->stats._query_hist)
			histogram_dump(si->stats._query_hist);
		if (si->stats._query_batch_lookup)
			histogram_dump(si->stats._query_batch_lookup);
		if (si->stats._query_batch_io)
			histogram_dump(si->stats._query_batch_io);
		if (si->stats._query_rcnt_hist)
			histogram_dump(si->stats._query_rcnt_hist);
		if (si->stats._query_diff_hist)
			histogram_dump(si->stats._query_diff_hist);
	}
	SINDEX_GUNLOCK();
	return AS_SINDEX_OK;
}

int
as_sindex_histogram_enable(as_namespace *ns, char * iname, bool enable)
{
	as_sindex *si = as_sindex_lookup_by_iname(ns, iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if (!si) {
		cf_warning(AS_SINDEX, "SINDEX HISTOGRAM : sindex %s not found", iname);
		return AS_SINDEX_ERR_NOTFOUND;
	}

	si->enable_histogram = enable;
	AS_SINDEX_RELEASE(si);
	return AS_SINDEX_OK;
}

/*
 * Client API function to set configuration parameters for secondary indexes
 */
int
as_sindex_set_config(as_namespace *ns, as_sindex_metadata *imd, char *params)
{
	if (!ns)
		return AS_SINDEX_ERR_PARAM;
	as_sindex *si = as_sindex_lookup_by_iname(ns, imd->iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if (!si) {
		return AS_SINDEX_ERR_NOTFOUND;
	}
	SINDEX_WLOCK(&si->imd->slock);
	if (si->state == AS_SINDEX_ACTIVE) {
		char context[100];
		int  context_len = sizeof(context);
		if (0 == as_info_parameter_get(params, "ignore-not-sync", context, &context_len)) {
			if (strncmp(context, "true", 4)==0 || strncmp(context, "yes", 3)==0) {
				cf_info(AS_INFO,"Changing value of ignore-not-sync of ns %s sindex %s to %s", ns->name, imd->iname, context);
				si->config.flag |= AS_SINDEX_CONFIG_IGNORE_ON_DESYNC;
			} else if (strncmp(context, "false", 5)==0 || strncmp(context, "no", 2)==0) {
				cf_info(AS_INFO,"Changing value of ignore-not-sync of ns %s sindex %s to %s", ns->name, imd->iname, context);
				si->config.flag &= ~AS_SINDEX_CONFIG_IGNORE_ON_DESYNC;
			} else {
				goto Error;
			}
		}
		else if (0 == as_info_parameter_get(params, "data-max-memory", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_detail(AS_INFO, "data-max-memory = %"PRIu64"",val);
			// Protect so someone does not reduce memory to below 1/2 current value, allow it
			// in case value is ULONG_MAX
			if (((si->config.data_max_memory != ULONG_MAX)
				&& (val < (si->config.data_max_memory / 2L)))
				|| (val < cf_atomic64_get(si->stats.mem_used))) {
				goto Error;
			}
			cf_info(AS_INFO,"Changing value of data-max-memory of ns %s sindex %s from %"PRIu64"to %"PRIu64"",
							ns->name, imd->iname, si->config.data_max_memory, val);
			si->config.data_max_memory = val;
		}
		else if (0 == as_info_parameter_get(params, "gc-period", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_detail(AS_INFO, "gc-period = %"PRIu64"",val);
			if (val < 0) {
				goto Error;
			}
			cf_info(AS_INFO,"Changing value of gc-period of ns %s sindex %s from %"PRIu64"to %"PRIu64"",
							ns->name, imd->iname, si->config.defrag_period, val);
			si->config.defrag_period = val;
		}
		else if (0 == as_info_parameter_get(params, "gc-max-units", context, &context_len)) {
			uint64_t val = atoll(context);
			cf_detail(AS_INFO, "gc-limit = %"PRIu64"",val);
			if (val < 0) {
				goto Error;
			}
			cf_info(AS_INFO,"Changing value of gc-max-units of ns %s sindex %s from %u to %lu",
							ns->name, imd->iname, si->config.defrag_max_units, val);
			si->config.defrag_max_units = val;
		}
		else {
			goto Error;
		}
	}
	SINDEX_UNLOCK(&si->imd->slock);
	AS_SINDEX_RELEASE(si);
	return AS_SINDEX_OK;

Error:
	SINDEX_UNLOCK(&si->imd->slock);
	AS_SINDEX_RELEASE(si);
	return AS_SINDEX_ERR_PARAM;
}

/*
 * Client API to list all the indexes in a namespace, returns list of imd with
 * index information, Caller should free it up
 */
int
as_sindex_list_str(as_namespace *ns, cf_dyn_buf *db)
{
	SINDEX_GRLOCK();
	for (int i = 0; i < AS_SINDEX_MAX; i++) {
		if (&(ns->sindex[i]) && (ns->sindex[i].imd)) {
			as_sindex si = ns->sindex[i];
			if (as_sindex_isactive(&si)) {
				SINDEX_RLOCK(&si.imd->slock);
			}
			cf_dyn_buf_append_string(db, "ns=");
			cf_dyn_buf_append_string(db, ns->name);
			cf_dyn_buf_append_string(db, ":set=");
			cf_dyn_buf_append_string(db, (si.imd->set) ? si.imd->set : "NULL");
			cf_dyn_buf_append_string(db, ":indexname=");
			cf_dyn_buf_append_string(db, si.imd->iname);
			cf_dyn_buf_append_string(db, ":bin=");
			cf_dyn_buf_append_buf(db, (uint8_t *)si.imd->bname, strlen(si.imd->bname));
			cf_dyn_buf_append_string(db, ":type=");
			cf_dyn_buf_append_string(db, as_sindex_ktype_str(si.imd->btype));
			cf_dyn_buf_append_string(db, ":indextype=");
			cf_dyn_buf_append_string(db, as_sindex_type_defs[si.imd->itype]);

			cf_dyn_buf_append_string(db, ":path=");
			cf_dyn_buf_append_string(db, si.imd->path_str);
			cf_dyn_buf_append_string(db, ":sync_state=");
			if (si.desync_cnt > 0) {
				cf_dyn_buf_append_string(db, "needsync");
			}
			else {
				cf_dyn_buf_append_string(db, "synced");
			}
			// Index State
			if (si.state == AS_SINDEX_ACTIVE) {
				if (si.flag & AS_SINDEX_FLAG_RACTIVE) {
					cf_dyn_buf_append_string(db, ":state=RW;");
				}
				else if (si.flag & AS_SINDEX_FLAG_WACTIVE) {
					cf_dyn_buf_append_string(db, ":state=WO;");
				}
				else {
					// should never come here.
					cf_dyn_buf_append_string(db, ":state=A;");
				}
			}
			else if (si.state == AS_SINDEX_INACTIVE) {
				cf_dyn_buf_append_string(db, ":state=I;");
			}
			else {
				cf_dyn_buf_append_string(db, ":state=D;");
			}
			if (as_sindex_isactive(&si)) {
				SINDEX_UNLOCK(&si.imd->slock);
			}
		}
	}
	SINDEX_GUNLOCK();
	return AS_SINDEX_OK;
}
//                                  END - STAT/CONFIG/HISTOGRAM
// ************************************************************************************************
// ************************************************************************************************
//                                         SI REFERENCE
// Reserve the sindex so it does not get deleted under the hood
int
as_sindex_reserve(as_sindex *si, char *fname, int lineno)
{
	if (!as_sindex_isactive(si)) {
		cf_warning(AS_SINDEX, "Trying to reserve sindex %s in a state other than active. State is %d",
							si->imd->iname, si->state);
	}
	if (si->imd) cf_rc_reserve(si->imd);
	int count = cf_rc_count(si->imd);
	cf_debug(AS_SINDEX, "Index %s:%s in %d state Reserved to reference count %d < 2 at %s:%d", 
							si->ns->name, si->imd->iname, si->state, count, fname, lineno);
	return AS_SINDEX_OK;
}

/*
 * Release, queue up the request for the destroy to clean up Aerospike Index thread,
 * Not done inline because main write thread could release the last reference.
 */
int
as_sindex_release(as_sindex *si, char *fname, int lineno)
{
	if (!si) return AS_SINDEX_OK;
	// Can be checked without locking
	uint64_t val = cf_rc_release(si->imd);
	if (val == 0) {
		cf_assert((si->state == AS_SINDEX_DESTROY),
					AS_SINDEX, CF_CRITICAL,
					" Invalid state at cleanup");
		cf_assert(!(si->state & AS_SINDEX_FLAG_DESTROY_CLEANUP),
					AS_SINDEX, CF_CRITICAL,
					" Invalid state at cleanup");
		si->flag |= AS_SINDEX_FLAG_DESTROY_CLEANUP;
		if (CF_QUEUE_OK != cf_queue_push(g_sindex_destroy_q, &si)) {
			return AS_SINDEX_ERR;
		}
	}
	else {
		SINDEX_RLOCK(&si->imd->slock);
		cf_debug(AS_SINDEX, "Index %s in %d state Released "
					"to reference count  %"PRIu64" < 2 at %s:%d",
					si->imd->iname, si->state, val, fname, lineno);
		// Display a warning when rc math is messed-up during sindex-delete
		if(si->state == AS_SINDEX_DESTROY){
			cf_info(AS_SINDEX,"Returning from a sindex destroy op for: %s:%s with reference count %"PRIu64"",
								si->ns->name, si->imd->iname, val);
		}
		SINDEX_UNLOCK(&si->imd->slock);
	}
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_populator_reserve_all(as_namespace * ns)
{
	if (!ns) {
		cf_warning(AS_SINDEX, "namespace found NULL");
		return AS_SINDEX_ERR;
	}

	int count = 0 ;
	int valid = 0;
	SINDEX_GRLOCK();
	while (valid < ns->sindex_cnt && count < AS_SINDEX_MAX) {
		as_sindex * si = &ns->sindex[count];
		if (as_sindex_isactive(si)) {
			AS_SINDEX_RESERVE(si);
			valid++;
		}
		count++;
	}
	SINDEX_GUNLOCK();
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_populator_release_all(as_namespace * ns)
{
	if (!ns) {
		cf_warning(AS_SINDEX, "namespace found NULL");
		return AS_SINDEX_ERR;
	}

	int count = 0 ;
	int valid = 0;
	SINDEX_GRLOCK();
	while (valid < ns->sindex_cnt && count < AS_SINDEX_MAX) {
		as_sindex * si = &ns->sindex[count];
		if (as_sindex_isactive(si)) {
			AS_SINDEX_RELEASE(si);
			valid++;
		}
		count++;
	}
	SINDEX_GUNLOCK();
	return AS_SINDEX_OK;
}

// Complementary function of as_sindex_arr_lookup_by_set_binid
void
as_sindex_release_arr(as_sindex *si_arr[], int si_arr_sz)
{
	for (int i=0; i<si_arr_sz; i++) {
		if (si_arr[i]) {
			AS_SINDEX_RELEASE(si_arr[i]);
		}
		else {
			cf_warning(AS_SINDEX, "SI is null");
		}
	}
}

//                                    END - SI REFERENCE
// ************************************************************************************************
// ************************************************************************************************
//                                          SINDEX CREATE
// simatch is index in sindex array
// nptr is index of pimd in imd
void
as_sindex__create_pmeta(as_sindex *si, int simatch, int nptr)
{
	if (!si) {
		cf_warning(AS_SINDEX, "SI is null");
		return;
	}

	if (nptr == 0) {
		cf_warning(AS_SINDEX, "nptr is 0");
		return;
	}

	si->imd->pimd = cf_malloc(nptr * sizeof(as_sindex_pmetadata));
	memset(si->imd->pimd, 0, nptr*sizeof(as_sindex_pmetadata));

	pthread_rwlockattr_t rwattr;
	if (pthread_rwlockattr_init(&rwattr))
		cf_crash(AS_AS,
				"pthread_rwlockattr_init: %s", cf_strerror(errno));
	if (pthread_rwlockattr_setkind_np(&rwattr,
				PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP))
		cf_crash(AS_TSVC,
				"pthread_rwlockattr_setkind_np: %s",cf_strerror(errno));

	for (int i = 0; i < nptr; i++) {
		as_sindex_pmetadata *pimd = &si->imd->pimd[i];
		if (pthread_rwlock_init(&pimd->slock, &rwattr)) {
			cf_crash(AS_SINDEX,
					"Could not create secondary index dml mutex ");
		}
		if (ai_post_index_creation_setup_pmetadata(si->imd, pimd,
													simatch, i)) {
			cf_crash(AS_SINDEX,
					"Something went reallly bad !!!");
		}
	}
}

/*
 * Description :
 *  	Checks the parameters passed to as_sindex_create function
 *
 * Parameters:
 * 		namespace, index metadata
 *
 * Returns:
 * 		AS_SINDEX_OK            - for valid parameters.
 * 		Appropriate error codes - otherwise
 *
 * Synchronization:
 * 		This function does not explicitly acquire any lock.
 * TODO : Check if exits_by_defn can be used instead of this
 */
int
as_sindex_create_check_params(as_namespace* ns, as_sindex_metadata* imd)
{
	SINDEX_GRLOCK();

	int ret     = AS_SINDEX_OK;
	if (ns->sindex_cnt >= AS_SINDEX_MAX) {
		ret = AS_SINDEX_ERR_MAXCOUNT;
		goto END;
	}

	int simatch = as_sindex__simatch_by_iname(ns, imd->iname);
	if (simatch != -1) {
		ret = AS_SINDEX_ERR_FOUND;
	} else {
		int16_t binid = as_bin_get_id(ns, imd->bname);
		if (binid != -1)
		{
			int simatch = as_sindex__simatch_by_set_binid(ns, imd->set, binid, imd->btype, imd->itype, imd->path_str);
			if (simatch != -1) {
				ret = AS_SINDEX_ERR_FOUND;
				goto END;
			}
		}
	}

END:
	SINDEX_GUNLOCK();
    return ret;
}

int
as_sindex_create(as_namespace *ns, as_sindex_metadata *imd, bool user_create)
{
	int ret = AS_SINDEX_ERR;
	// Ideally there should be one lock per namespace, but because the
	// Aerospike Index metadata is single global structure we need a overriding
	// lock for that. NB if it becomes per namespace have a file lock
	SINDEX_GWLOCK();
	if (as_sindex_lookup_by_iname_lockfree(ns, imd->iname, AS_SINDEX_LOOKUP_FLAG_NORESERVE)) {
		cf_detail(AS_SINDEX,"Index %s already exists", imd->iname);
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR_FOUND;
	}
	int chosen_id = AS_SINDEX_MAX;
	as_sindex *si = NULL;
	for (int i = 0; i < AS_SINDEX_MAX; i++) {
		if (ns->sindex[i].state == AS_SINDEX_INACTIVE) {
			si = &ns->sindex[i];
			chosen_id = i;
			break;
		}
	}

	if (!si || (chosen_id == AS_SINDEX_MAX))  {
		cf_warning(AS_SINDEX, "SINDEX CREATE : Maxed out secondary index limit no more indexes allowed");
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR;
	}

	imd->nprts  = ns->sindex_num_partitions;
	int id      = chosen_id;
	si          = &ns->sindex[id];
	as_sindex_metadata *qimd;

	if (as_sindex__populate_binid(ns, imd)) {
		cf_warning(AS_SINDEX, "SINDEX CREATE : Popluating bin id failed");
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR_PARAM;
	}

	char si_prop[AS_SINDEX_PROP_KEY_SIZE];
	int si_prop_len = sizeof(si_prop);
	memset(si_prop, 0, si_prop_len);
	if (!imd->set) {
		// sindex can be over a NULL set
		sprintf(si_prop, "_%d_%d", imd->binid, imd->btype);
	}
	else {
		sprintf(si_prop, "%s_%d_%d", imd->set, imd->binid, imd->btype);
	}

	as_sindex_status rv = as_sindex__put_in_set_binid_hash(ns, imd->set, imd->binid, id);
	if (rv != AS_SINDEX_OK) {
		cf_warning(AS_SINDEX, "SINDEX CREATE : Put in set_binid hash fails with error %d", rv);
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR;
	}

	cf_detail(AS_SINDEX, "Put binid simatch %d->%d", imd->binid, chosen_id);

	char iname[AS_ID_INAME_SZ];
	memset(iname, 0, AS_ID_INAME_SZ);
	snprintf(iname, strlen(imd->iname)+1, "%s", imd->iname);
	if (SHASH_OK != shash_put(ns->sindex_iname_hash, (void *)iname, (void *)&chosen_id)) {
		cf_warning(AS_SINDEX, "Internal error ... Duplicate element found sindex iname hash [%s %s]",
						imd->iname, as_bin_get_name_from_id(ns, imd->binid));

		rv = as_sindex__delete_from_set_binid_hash(ns, imd);
		if (rv) {
			cf_warning(AS_SINDEX, "Delete from set_binid hash fails with error %d", rv);
		}
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR;
	}
	cf_detail(AS_SINDEX, "Put iname simatch %s:%zu->%d", iname, strlen(imd->iname), chosen_id);

	as_sindex__dup_meta(imd, &qimd, true);
	qimd->si    = si;
	qimd->nprts = imd->nprts;
	int bimatch = -1;

	ret = ai_btree_create(qimd, id, &bimatch, imd->nprts);
	if (!ret) { // create ref counted index metadata & hang it from sindex
		si->imd         = qimd;
		si->imd->bimatch = bimatch;
		si->state       = AS_SINDEX_ACTIVE;
		as_sindex_set_binid_has_sindex(ns, si->imd->binid);
		si->desync_cnt  = 0;
		si->flag        = AS_SINDEX_FLAG_WACTIVE;
		si->new_imd     = NULL;
		as_sindex__create_pmeta(si, id, imd->nprts);
		// Always tune si to default settings to start with
		as_sindex__config_default(si);

		// If this si has a valid config-item and this si was created by smd boot-up,
		// then set the config-variables from si_cfg_array.

		// si_cfg_var_hash is deliberately kept as a transient structure.
		// Its applicable only for boot-time si-creation via smd
		// In the case of sindex creations via aql, i.e dynamic si creation,
		// this array wont exist and all si configs will be default configs.
		if (ns->sindex_cfg_var_hash) {
			// Check for duplicate si stanzas with the same si-name ?
			as_sindex_config_var check_si_conf;

			if (SHASH_OK == shash_get(ns->sindex_cfg_var_hash, (void *)iname, (void *)&check_si_conf)){
				// A valid config stanza exists for this si entry
				// Copy the config over to the new si
				// delete the old hash entry
				cf_info(AS_SINDEX,"Found custom configuration for SI:%s, applying", imd->iname);
				as_sindex_config_var_copy(si, &check_si_conf);
				shash_delete(ns->sindex_cfg_var_hash,  (void *)iname);
				check_si_conf.conf_valid_flag = true;
				shash_put_unique(ns->sindex_cfg_var_hash, (void *)iname, (void *)&check_si_conf);
			}
		}

		as_sindex__setup_histogram(si);
		as_sindex__stats_clear(si);

		ns->sindex_cnt++;
		si->ns          = ns;
		si->simatch     = chosen_id;
		as_sindex_reserve_data_memory(si->imd, ai_btree_get_isize(si->imd));

		// Only trigger scan if this create is done after boot
		if (user_create && g_sindex_boot_done) {
			// Reserve it before pushing it into queue
			AS_SINDEX_RESERVE(si);
			SINDEX_GUNLOCK();
			int rv = cf_queue_push(g_sindex_populate_q, &si);
			if (CF_QUEUE_OK != rv) {
				cf_warning(AS_SINDEX, "Failed to queue up for population... index=%s "
							"Internal Queue Error rv=%d, try dropping and recreating",
							si->imd->iname, rv);
			}
		} else {
			// Internal create is called before storage is initialized. Loading
			// of storage will fill up the indexes no need to queue it up for scan
			SINDEX_GUNLOCK();
		}
	} else {
		// TODO: When alc_btree_create fails, accept_cb should have a better
		//       way to handle failure. Currently it maintains a dummy si
		//       structures with not created flag. accept_cb should repair
		//       such dummy si structures and retry alc_btree_create.
		shash_delete(ns->sindex_iname_hash, (void *)iname);
		rv = as_sindex__delete_from_set_binid_hash(ns, imd);
		if (rv) {
			cf_warning(AS_SINDEX, "Delete from set_binid hash fails with error %d", rv);
		}
		as_sindex_imd_free(qimd);
		cf_debug(AS_SINDEX, "Create index %s failed ret = %d",
				imd->iname, ret);
		SINDEX_GUNLOCK();
	}
	return ret;
}

/*
 * Description     : When a index has to be dropped and recreated during cluster state change
 * 				     this function is called.
 * Parameters      : imd, which is constructed from the final index defn given by paxos principal.
 *
 * Returns         : 0 on all cases. Check log for errors.
 *
 * Synchronization : Does not explicitly take any locks
 */
int
as_sindex_update(as_sindex_metadata* imd)
{
	as_namespace *ns = as_namespace_get_byname(imd->ns_name);
	int ret          = as_sindex_create(ns, imd, true);
	if (ret != 0) {
		cf_warning(AS_SINDEX,"Index %s creation failed at the accept callback", imd->iname);
	}
	return 0;
}
//                                       END - SINDEX CREATE
// ************************************************************************************************
// ************************************************************************************************
//                                         SINDEX DELETE

void
as_sindex_destroy_pmetadata(as_sindex *si)
{
	for (int i = 0; i < si->imd->nprts; i++) {
		as_sindex_pmetadata *pimd = &si->imd->pimd[i];
		pthread_rwlock_destroy(&pimd->slock);
	}
	as_sindex__destroy_histogram(si);
	cf_free(si->imd->pimd);
	si->imd->pimd = NULL;
}

// TODO : Will not harm if it reserves and releases the sindex
// Keep it simple
bool
as_sindex_delete_checker(as_namespace *ns, as_sindex_metadata *imd)
{
	if (as_sindex_lookup_by_iname_lockfree(ns, imd->iname,
			AS_SINDEX_LOOKUP_FLAG_NORESERVE | AS_SINDEX_LOOKUP_FLAG_ISACTIVE)) {
		return true;
	} else {
		return false;
	}
}

/*
 * Client API to destroy secondary index, mark destroy
 * Deletes via smd or info-command user-delete requests.
 */
int
as_sindex_destroy(as_namespace *ns, as_sindex_metadata *imd)
{
	SINDEX_GWLOCK();
	as_sindex *si   = as_sindex_lookup_by_iname_lockfree(ns, imd->iname,
						AS_SINDEX_LOOKUP_FLAG_NORESERVE | AS_SINDEX_LOOKUP_FLAG_ISACTIVE);

	if (si) {
		if (imd->post_op == 1) {
			as_sindex__dup_meta(imd, &si->new_imd, false);
		}
		else {
			si->new_imd = NULL;
		}
		si->state = AS_SINDEX_DESTROY;
		as_sindex_reset_binid_has_sindex(ns, imd->binid);
		AS_SINDEX_RELEASE(si);
		SINDEX_GUNLOCK();
		return AS_SINDEX_OK;
	} else {
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR_NOTFOUND;
	}
}

// On emptying a index
// 		reset objects and keys
// 		reset memory used 
// 		add previous number of objects as deletes 
void
as_sindex_clear_stats_on_empty_index(as_sindex * si)
{
	as_sindex_release_data_memory(si->imd, si->stats.mem_used);	
	as_sindex_reserve_data_memory(si->imd, ai_btree_get_isize(si->imd));

	cf_atomic64_add(&si->stats.n_deletes, cf_atomic64_get(si->stats.n_objects));
	cf_atomic64_set(&si->stats.n_keys, 0);
	cf_atomic64_set(&si->stats.n_objects, 0);
}

void
as_sindex_empty_index(as_sindex_metadata * imd)
{
	as_sindex_pmetadata * pimd;
	for (int i=0; i<imd->nprts; i++) {
		SINDEX_RLOCK(&imd->slock);
		pimd = &imd->pimd[i];
		SINDEX_WLOCK(&pimd->slock);
		struct btree * ibtr = pimd->ibtr;
		ai_btree_reinit_pimd(pimd);
		SINDEX_UNLOCK(&pimd->slock);
		SINDEX_UNLOCK(&imd->slock);
		ai_btree_delete_ibtr(ibtr, pimd->imatch);
	}
	as_sindex_clear_stats_on_empty_index(imd->si);
}

void
as_sindex_delete_set(as_namespace * ns, char * set_name)
{
	SINDEX_GRLOCK();
	as_sindex * si_arr[ns->sindex_cnt];
	int sindex_count = as_sindex_arr_lookup_by_setname_lockfree(ns, set_name, si_arr);

	for (int i=0; i<sindex_count; i++) {
		cf_info(AS_SINDEX, "Initiating si set delete for index %s in set %s", si_arr[i]->imd->iname, set_name);
		as_sindex_empty_index(si_arr[i]->imd);
		cf_info(AS_SINDEX, "Finished si set delete for index %s in set %s", si_arr[i]->imd->iname, set_name);
	}
	SINDEX_GUNLOCK();
	as_sindex_release_arr(si_arr, sindex_count);
}
//                                        END - SINDEX DELETE
// ************************************************************************************************
// ************************************************************************************************
//                                         SINDEX POPULATE
/*
 * Client API to mark index population finished, tick it ready for read
 */
int
as_sindex_populate_done(as_sindex *si)
{
	int ret = AS_SINDEX_OK;
	SINDEX_WLOCK(&si->imd->slock);
	// Setting flag is atomic: meta lockless
	si->flag |= AS_SINDEX_FLAG_RACTIVE;
	si->flag &= ~AS_SINDEX_FLAG_POPULATING;
	SINDEX_UNLOCK(&si->imd->slock);
	return ret;
}
/*
 * Client API to start namespace scan to populate secondary index. The scan
 * is only performed in the namespace is warm start or if its data is not in
 * memory and data is loaded from. For cold start with data in memory the indexes
 * are populate upfront.
 *
 * This call is only made at the boot time.
 */
int
as_sindex_boot_populateall()
{
	// Initialize the secondary index builder. The thread pool is initialized
	// with maximum threads to go full throttle, then down-sized to the
	// configured number after the startup population job is done.
	as_sbld_init();

	int ns_cnt = 0;

	// Trigger namespace scan to populate all secondary indexes
	// mark all secondary index for a namespace as populated
	for (int i = 0; i < g_config.n_namespaces; i++) {
		as_namespace *ns = g_config.namespaces[i];
		if (!ns || (ns->sindex_cnt == 0)) {
			continue;
		}

		// If FAST START
		// OR (Data not in memory AND COLD START)
		if (!ns->cold_start
			|| (!ns->storage_data_in_memory)) {
			// reserve all sindexes
			as_sindex_populator_reserve_all(ns);
			as_sbld_build_all(ns);
			cf_info(AS_SINDEX, "Queuing namespace %s for sindex population ", ns->name);
		} else {
			as_sindex_boot_populateall_done(ns);
		}
		ns_cnt++;
	}
	for (int i = 0; i < ns_cnt; i++) {
		int ret;
		// blocking call, wait till an item is popped out of Q :
		cf_queue_pop(g_sindex_populateall_done_q, &ret, CF_QUEUE_FOREVER);
		// TODO: Check for failure .. is generally fatal if it fails
	}

	for (int i = 0; i < g_config.n_namespaces; i++) {
		as_namespace *ns = g_config.namespaces[i];
		if (!ns || (ns->sindex_cnt == 0)) {
			continue;
		}

		// If FAST START
		// OR (Data not in memory AND COLD START)
		if (!ns->cold_start || (!ns->storage_data_in_memory)) {
			as_sindex_populator_release_all(ns);
		}
	}

	// Down-size builder thread pool to configured value.
	as_sbld_resize_thread_pool(g_config.sindex_builder_threads);

	g_sindex_boot_done = true;

	// This above flag indicates that the basic sindex boot-up loader is done
	// Go and destroy the sindex_cfg_var_hash here to prevent run-time
	// si's from getting the config-file settings.
	for (int i = 0; i < g_config.n_namespaces; i++) {
		as_namespace *ns = g_config.namespaces[i];

		if (ns->sindex_cfg_var_hash) {
			shash_reduce(ns->sindex_cfg_var_hash, as_sindex_cfg_var_hash_reduce_fn, NULL);
	    	shash_destroy(ns->sindex_cfg_var_hash);

	    	// Assign hash to NULL at the start and end of its lifetime
			ns->sindex_cfg_var_hash = NULL;
		}

	}

	return AS_SINDEX_OK;
}

/*
 * Client API to mark all the indexes in namespace populated and ready for read
 */
int
as_sindex_boot_populateall_done(as_namespace *ns)
{
	SINDEX_GWLOCK();
	int ret = AS_SINDEX_OK;

	for (int i = 0; i < AS_SINDEX_MAX; i++) {
		as_sindex *si = &ns->sindex[i];
		if (!as_sindex_isactive(si))  continue;
		// This sindex is getting populating by it self scan
		if (si->flag & AS_SINDEX_FLAG_POPULATING) continue;
		si->flag |= AS_SINDEX_FLAG_RACTIVE;
	}
	SINDEX_GUNLOCK();
	cf_queue_push(g_sindex_populateall_done_q, &ret);
	cf_info(AS_SINDEX, "Namespace %s sindex population done", ns->name);
	return ret;
}

// TODO : sindex repair should drop the index and repopulate it
// Currently we only populate the sindex again. This does not clean the uncleanable
// garbage accumulated in the secondary index tree.
int
as_sindex_repair(as_namespace *ns, char * iname)
{
	as_sindex *si = as_sindex_lookup_by_iname(ns, iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if (si) {
		if (si->desync_cnt == 0) {
			cf_warning(AS_SINDEX, "SINDEX REPAIR : index %s is found in sync with primary."
						" No need to repair index", iname);
			AS_SINDEX_RELEASE(si);
			return AS_SINDEX_OK;
		}
		int rv = cf_queue_push(g_sindex_populate_q, &si);
		if (CF_QUEUE_OK != rv) {
			cf_warning(AS_SINDEX, "SINDEX REPAIR : Failed to queue up for population. index=%s "
					"Internal Queue Error rv=%d, retry repair", si->imd->iname, rv);
			AS_SINDEX_RELEASE(si);
			return AS_SINDEX_ERR;
		}
		return AS_SINDEX_OK;
	}
	else {
		cf_warning(AS_SINDEX, "SINDEX REPAIR : index %s not found", iname);
	}
	return AS_SINDEX_ERR_NOTFOUND;
}
//                                            END - SINDEX POPULATE
// ************************************************************************************************
// ************************************************************************************************
//                                       SINDEX BIN PATH
as_sindex_status
as_sindex_add_mapkey_in_path(as_sindex_metadata * imd, char * path_str, int start, int end)
{
	if (end < start) {
		return AS_SINDEX_ERR;
	}

	int path_length = imd->path_length;
	char int_str[20];
	strncpy(int_str, path_str+start, end-start+1);
	int_str[end-start+1] = '\0';
	char * str_part;
	imd->path[path_length-1].value.key_int = strtol(int_str, &str_part, 10);
	if (str_part == int_str || (*str_part != '\0')) {
		imd->path[path_length-1].value.key_str  = cf_strndup(int_str, strlen(int_str)+1);
		imd->path[path_length-1].mapkey_type = AS_PARTICLE_TYPE_STRING;
	}
	else {
		imd->path[path_length-1].mapkey_type = AS_PARTICLE_TYPE_INTEGER;
	}
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_add_listelement_in_path(as_sindex_metadata * imd, char * path_str, int start, int end)
{
	if (end < start) {
		return AS_SINDEX_ERR;
	}
	int path_length = imd->path_length;
	char int_str[10];
	strncpy(int_str, path_str+start, end-start+1);
	int_str[end-start+1] = '\0';
	char * str_part;
	imd->path[path_length-1].value.index = strtol(int_str, &str_part, 10);
	if (str_part == int_str || (*str_part != '\0')) {
		return AS_SINDEX_ERR;
	}
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_parse_subpath(as_sindex_metadata * imd, char * path_str, int start, int end)
{
	int path_len = strlen(path_str);
	bool overflow = end >= path_len ? true : false;

	if (start == 0 ) {
		if (overflow) {
			imd->bname = cf_strndup(path_str+start, end-start);
		}
		else if (path_str[end] == '.') {
			imd->bname = cf_strndup(path_str+start, end-start);
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_MAP;
		}
		else if (path_str[end] == '[') {
			imd->bname = cf_strndup(path_str+start, end-start);
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_LIST;
		}
		else {
			return AS_SINDEX_ERR;
		}
	}
	else if (path_str[start] == '.') {
		if (overflow) {
			if (as_sindex_add_mapkey_in_path(imd, path_str, start+1, end-1) != AS_SINDEX_OK) {
				return AS_SINDEX_ERR;
			}
		}
		else if (path_str[end] == '.') {
			// take map value
			if (as_sindex_add_mapkey_in_path(imd, path_str, start+1, end-1) != AS_SINDEX_OK) {
				return AS_SINDEX_ERR;
			}
			// add type for next node in path
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_MAP;
		}
		else if (path_str[end] == '[') {
			// value
			if (as_sindex_add_mapkey_in_path(imd, path_str, start+1, end-1) != AS_SINDEX_OK) {
				return AS_SINDEX_ERR;
			}
			// add type for next node in path
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_LIST;
		}
		else {
			return AS_SINDEX_ERR;
		}
	}
	else if (path_str[start] == '[') {
		if (!overflow && path_str[end] == ']') {
			//take list value
			if (as_sindex_add_listelement_in_path(imd, path_str, start+1, end-1) != AS_SINDEX_OK) {
				return AS_SINDEX_ERR;
			}
		}
		else {
			return AS_SINDEX_ERR;
		}
	}
	else if (path_str[start] == ']') {
		if (end - start != 1) {
			return AS_SINDEX_ERR;
		}
		else if (overflow) {
			return AS_SINDEX_OK;
		}
		if (path_str[end] == '.') {
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_MAP;
		}
		else if (path_str[end] == '[') {
			imd->path_length++;
			imd->path[imd->path_length-1].type = AS_PARTICLE_TYPE_LIST;
		}
		else {
			return AS_SINDEX_ERR;
		}
	}
	else {
		return AS_SINDEX_ERR;
	}
	return AS_SINDEX_OK;
}
/*
 * This function parses the path_str and populate array of path structure in
 * imd.
 * Each element of the path is the way to reach the the next path.
 * For e.g
 * bin.k1[1][0]
 * array of the path structure would be like -
 * path[0].type = AS_PARTICLE_TYPE_MAP . path[0].value.key_str = k1  path[0].value.ke
 * path[1].type = AS_PARTICLE_TYPE_LIST . path[1].value.index  = 1
 * path[2].type = AS_PARTICLE_TYPE_LIST . path[2].value.index  = 0
*/
as_sindex_status
as_sindex_extract_bin_path(as_sindex_metadata * imd, char * path_str)
{
	int    path_len    = strlen(path_str);
	int    start       = 0;
	int    end         = 0;
	if (path_len > AS_SINDEX_MAX_PATH_LENGTH) {
		cf_warning(AS_SINDEX, "Bin path length exceeds the maximum allowed.");
		return AS_SINDEX_ERR;
	}
	// Iterate through the path_str and search for character (., [, ])
	// which leads to sublevels in maps and lists
	while (end < path_len) {
		if (path_str[end] == '.' || path_str[end] == '[' || path_str[end] == ']') {
			if (as_sindex_parse_subpath(imd, path_str, start, end)!=AS_SINDEX_OK) {
				return AS_SINDEX_ERR;
			}
			start = end;
			if (imd->path_length >= AS_SINDEX_MAX_DEPTH) {
				cf_warning(AS_SINDEX, "Bin position depth level exceeds the max depth allowed %d", AS_SINDEX_MAX_DEPTH);
				return AS_SINDEX_ERR;
			}
		}
		end++;
	}
	if (as_sindex_parse_subpath(imd, path_str, start, end)!=AS_SINDEX_OK) {
		return AS_SINDEX_ERR;
	}
/*
// For debugging
	cf_info(AS_SINDEX, "After parsing : bin name: %s", imd->bname);
	for (int i=0; i<imd->path_length; i++) {
		if(imd->path[i].type == AS_PARTICLE_TYPE_MAP ) {
			if (imd->path[i].key_type == AS_PARTICLE_TYPE_INTEGER) {
				cf_info(AS_SINDEX, "map key_int %d", imd->path[i].value.key_int);
			}
			else if (imd->path[i].key_type == AS_PARTICLE_TYPE_STRING){
				cf_info(AS_SINDEX, "map key_str %s", imd->path[i].value.key_str);
			}
			else {
				cf_info(AS_SINDEX, "ERROR EEROR EERROR ERRROR REERROR");
			}
		}
		else{
			cf_info(AS_SINDEX, "list index %d", imd->path[i].value.index);
		}
	}
*/
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_extract_bin_from_path(char * path_str, char *bin)
{
	int    path_len    = strlen(path_str);
	int    end         = 0;
	if (path_len > AS_SINDEX_MAX_PATH_LENGTH) {
		cf_warning(AS_SINDEX, "Bin path length exceeds the maximum allowed.");
		return AS_SINDEX_ERR;
	}

	while (end < path_len && path_str[end] != '.' && path_str[end] != '[' && path_str[end] != ']') {
		end++;
	}

	if (end > 0 && end < AS_ID_BIN_SZ) {
		strncpy(bin, path_str, end);
		bin[end] = '\0';
	}
	else {
		return AS_SINDEX_ERR;
	}

	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_destroy_value_path(as_sindex_metadata * imd)
{
	for (int i=0; i<imd->path_length; i++) {
		if (imd->path[i].type == AS_PARTICLE_TYPE_MAP &&
				imd->path[i].mapkey_type == AS_PARTICLE_TYPE_STRING) {
			cf_free(imd->path[i].value.key_str);
		}
	}
	return AS_SINDEX_OK;
}

/*
 * This function checks the existence of path stored in the sindex metadata
 * in a bin
 */
as_val *
as_sindex_extract_val_from_path(as_sindex_metadata * imd, as_val * v)
{
	if (!v) {
		return NULL;
	}

	as_val * val = v;

	as_particle_type imd_btype = as_sindex_pktype(imd);
	if (imd->path_length == 0) {
		goto END;
	}
	as_sindex_path *path = imd->path;
	for (int i=0; i<imd->path_length; i++) {
		switch(val->type) {
			case AS_STRING:
			case AS_INTEGER:
				return NULL;
			case AS_LIST: {
				if (path[i].type != AS_PARTICLE_TYPE_LIST) {
					return NULL;
				}
				int index = path[i].value.index;
				as_arraylist* list  = (as_arraylist*) as_list_fromval(val);
				as_arraylist_iterator it;
				as_arraylist_iterator_init( &it, list);
				int j = 0;
				while( as_arraylist_iterator_has_next( &it) && j<=index) {
					val = (as_val*) as_arraylist_iterator_next( &it);
					j++;
				}
				if (j-1 != index ) {
					return NULL;
				}
				break;
			}
			case AS_MAP: {
				if (path[i].type != AS_PARTICLE_TYPE_MAP) {
					return NULL;
				}
				as_map * map = as_map_fromval(val);
				as_val * key;
				if (path[i].mapkey_type == AS_PARTICLE_TYPE_STRING) {
					key = (as_val *)as_string_new(path[i].value.key_str, false);
				}
				else if (path[i].mapkey_type == AS_PARTICLE_TYPE_INTEGER) {
					key = (as_val *)as_integer_new(path[i].value.key_int);
				}
				else {
					cf_warning(AS_SINDEX, "Possible false data in sindex metadata");
					return NULL;
				}
				val = as_map_get(map, key);
				if (key) {
					as_val_destroy(key);
				}
				if ( !val ) {
					return NULL;
				}
				break;
			}
			default:
				return NULL;
		}
	}

END:
	if (imd->itype == AS_SINDEX_ITYPE_DEFAULT) {
		if (val->type == AS_INTEGER && imd_btype == AS_PARTICLE_TYPE_INTEGER) {
			return val;
		}
		else if (val->type == AS_STRING && imd_btype == AS_PARTICLE_TYPE_STRING) {
			return val;
		}
	}
	else if (imd->itype == AS_SINDEX_ITYPE_MAPKEYS ||  imd->itype == AS_SINDEX_ITYPE_MAPVALUES) {
		if (val->type == AS_MAP) {
			return val;
		}
	}
	else if (imd->itype == AS_SINDEX_ITYPE_LIST) {
		if (val->type == AS_LIST) {
			return val;
		}
	}
	return NULL;
}
//                                        END - SINDEX BIN PATH
// ************************************************************************************************
// ************************************************************************************************
//                                                SINDEX QUERY
/*
 * Returns -
 * 		NULL - On failure
 * 		si   - On success.
 * Notes -
 * 		Reserves the si if found in the srange
 * 		Releases the si if imd is null or bin type is mis matched.
 *
 */
as_sindex *
as_sindex_from_range(as_namespace *ns, char *set, as_sindex_range *srange)
{
	cf_debug(AS_SINDEX, "as_sindex_from_range");
	if (ns->single_bin) {
		cf_warning(AS_SINDEX, "Secondary index query not allowed on single bin namespace %s", ns->name);
		return NULL;
	}
	as_sindex *si = as_sindex_lookup_by_defns(ns, set, srange->start.id,
						as_sindex_sktype_from_pktype(srange->start.type), srange->itype, srange->bin_path,
						AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if (si && si->imd) {
		// Do the type check
		as_sindex_metadata *imd = si->imd;
		if ((imd->binid == srange->start.id) && (srange->start.type != as_sindex_pktype(imd))) {
			cf_warning(AS_SINDEX, "Query and Index Bin Type Mismatch: "
					"[binid %d : Index Bin type %d : Query Bin Type %d]",
					imd->binid, as_sindex_pktype(imd), srange->start.type );
			AS_SINDEX_RELEASE(si);
			return NULL;
		}
	}
	return si;
}

/*
 * The way to filter out imd information from the as_msg which is primarily
 * query with all the details. For the normal operations the imd is formed out
 * of the as_op.
 */
/*
 * Returns -
 * 		NULL      - On failure.
 * 		as_sindex - On success.
 *
 * Description -
 * 		Firstly obtains the simatch using ns name and set name.
 * 		Then returns the corresponding slot from sindex array.
 *
 * TODO
 * 		log messages
 */
as_sindex *
as_sindex_from_msg(as_namespace *ns, as_msg *msgp)
{
	cf_debug(AS_SINDEX, "as_sindex_from_msg");
	as_msg_field *ifp  = as_msg_field_get(msgp, AS_MSG_FIELD_TYPE_INDEX_NAME);
	as_msg_field *sfp  = as_msg_field_get(msgp, AS_MSG_FIELD_TYPE_SET);

	if (!ifp) {
		cf_debug(AS_SINDEX, "Index name not found in the query request");
		return NULL;
	}

	char *setname = NULL;
	char *iname   = NULL;

	if (sfp) {
		setname   = cf_strndup((const char *)sfp->data, as_msg_field_get_value_sz(sfp));
	}
	iname         = cf_strndup((const char *)ifp->data, as_msg_field_get_value_sz(ifp));

	as_sindex *si = as_sindex_lookup_by_iname(ns, iname, AS_SINDEX_LOOKUP_FLAG_ISACTIVE);
	if (!si) {
		cf_detail(AS_SINDEX, "Search did not find index ");
	}

	if (sfp)   cf_free(setname);
	if (iname) cf_free(iname);
	return si;
}


/*
 * Internal Function - as_sindex_range_free
 * 		frees the sindex range
 *
 * Returns
 * 		AS_SINDEX_OK - In every case
 */
int
as_sindex_range_free(as_sindex_range **range)
{
	cf_debug(AS_SINDEX, "as_sindex_range_free");
	as_sindex_range *sk = (*range);
	if (sk->region) {
		geo_region_destroy(sk->region);
	}
	cf_free(sk);
	return AS_SINDEX_OK;
}

/*
 * Extract out range information from the as_msg and create the irange structure
 * if required allocates the memory.
 * NB: It is responsibility of caller to call the cleanup routine to clean the
 * range structure up and free up its memory
 *
 * query range field layout: contains - numranges, binname, start, end
 *
 * generic field header
 * 0   4 size = size of data only
 * 4   1 field_type = CL_MSG_FIELD_TYPE_INDEX_RANGE
 *
 * numranges
 * 5   1 numranges (max 255 ranges)
 *
 * binname
 * 6   1 binnamelen b
 * 7   b binname
 *
 * particle (start & end)
 * +b    1 particle_type
 * +b+1  4 start_particle_size x
 * +b+5  x start_particle_data
 * +b+5+x      4 end_particle_size y
 * +b+5+x+y+4   y end_particle_data
 *
 * repeat "numranges" times from "binname"
 */


/*
 * Function as_sindex_assert_query
 * Returns -
 * 		Return value of as_sindex__pre_op_assert
 */
int
as_sindex_assert_query(as_sindex *si, as_sindex_range *range)
{
	return as_sindex__pre_op_assert(si, AS_SINDEX_OP_READ);
}

/*
 * Function as_sindex_binlist_from_msg
 *
 * Returns -
 * 		binlist - On success
 * 		NULL    - On failure
 *
 */
cf_vector *
as_sindex_binlist_from_msg(as_namespace *ns, as_msg *msgp, int * num_bins)
{
	cf_debug(AS_SINDEX, "as_sindex_binlist_from_msg");
	as_msg_field *bfp = as_msg_field_get(msgp, AS_MSG_FIELD_TYPE_QUERY_BINLIST);
	if (!bfp) {
		return NULL;
	}
	const uint8_t *data = bfp->data;
	int numbins         = *data++;
	*num_bins           = numbins;

	cf_vector *binlist  = cf_vector_create(AS_ID_BIN_SZ, numbins, 0);

	for (int i = 0; i < numbins; i++) {
		int binnamesz = *data++;
		if (binnamesz <= 0 || binnamesz > AS_ID_BIN_SZ - 1) {
			cf_warning(AS_SINDEX, "Size of the bin name in bin list of sindex query is out of bounds. Size %d", binnamesz);
			cf_vector_destroy(binlist);
			return NULL;
		}
		char binname[AS_ID_BIN_SZ];
		memcpy(&binname, data, binnamesz);
		binname[binnamesz] = 0;
		cf_vector_set(binlist, i, (void *)binname);
		data     += binnamesz;
	}

	cf_debug(AS_SINDEX, "Queried Bin List %d ", numbins);
	for (int i = 0; i < cf_vector_size(binlist); i++) {
		char binname[AS_ID_BIN_SZ];
		cf_vector_get(binlist, i, (void*)&binname);
		cf_debug(AS_SINDEX,  " String Queried is |%s| \n", binname);
	}

	return binlist;
}

/*
 * Returns -
 *		AS_SINDEX_OK        - On success.
 *		AS_SINDEX_ERR_PARAM - On failure.
 *		AS_SINDEX_ERR_BIN_NOTFOUND - On failure.
 *
 * Description -
 *		Frames a sane as_sindex_range from msg.
 *
 *		We are not supporting multiranges right now. So numrange is always expected to be 1.
 */
int
as_sindex_range_from_msg(as_namespace *ns, as_msg *msgp, as_sindex_range *srange)
{
	cf_debug(AS_SINDEX, "as_sindex_range_from_msg");
	srange->num_binval = 0;
	// Ensure region is initialized in case we need to return an error code early.
	srange->region = NULL;

	// getting ranges
	as_msg_field *itype_fp  = as_msg_field_get(msgp, AS_MSG_FIELD_TYPE_INDEX_TYPE);
	as_msg_field *rfp = as_msg_field_get(msgp, AS_MSG_FIELD_TYPE_INDEX_RANGE);
	if (!rfp) {
		cf_warning(AS_SINDEX, "Required Index Range Not Found");
		return AS_SINDEX_ERR_PARAM;
	}
	const uint8_t *data = rfp->data;
	int numrange        = *data++;

	if (numrange != 1) {
		cf_warning(AS_SINDEX,
					"can't handle multiple ranges right now %d", rfp->data[0]);
		return AS_SINDEX_ERR_PARAM;
	}
	// NOTE - to support geospatial queries the srange object is actually a vector
	// of MAX_REGION_CELLS elements.  Normal queries only use the first element.
	// Geospatial queries use multiple elements.
	//
	memset(srange, 0, sizeof(as_sindex_range) * MAX_REGION_CELLS);
	if (itype_fp) {
		srange->itype = *itype_fp->data;
	}
	else {
		srange->itype = AS_SINDEX_ITYPE_DEFAULT;
	}
	for (int i = 0; i < numrange; i++) {
		as_sindex_bin_data *start = &(srange->start);
		as_sindex_bin_data *end   = &(srange->end);
		// Populate Bin id
		uint8_t bin_path_len         = *data++;
		if (bin_path_len >= AS_SINDEX_MAX_PATH_LENGTH) {
			cf_warning(AS_SINDEX, "Index position size %d exceeds the max length %d", bin_path_len, AS_SINDEX_MAX_PATH_LENGTH);
			return AS_SINDEX_ERR_PARAM;
		}

		strncpy(srange->bin_path, (char *)data, bin_path_len);
		srange->bin_path[bin_path_len] = '\0';

		char binname[AS_ID_BIN_SZ];
		if (as_sindex_extract_bin_from_path(srange->bin_path, binname) == AS_SINDEX_OK) {
			int16_t id = as_bin_get_id(ns, binname);
			if (id != -1) {
				start->id   = id;
				end->id     = id;
			} else {
				return AS_SINDEX_ERR_BIN_NOTFOUND;
			}
		}
		else {
			return AS_SINDEX_ERR_PARAM;
		}

		data       += bin_path_len;

		// Populate type
		int type    = *data++;
		start->type = type;
		end->type   = start->type;

		if ((type == AS_PARTICLE_TYPE_INTEGER)) {
			// get start point
			uint32_t startl  = ntohl(*((uint32_t *)data));
			data            += sizeof(uint32_t);
			if (startl != 8) {
				cf_warning(AS_SINDEX,
					"Can only handle 8 byte numerics right now %u", startl);
				goto Cleanup;
			}
			start->u.i64  = __cpu_to_be64(*((uint64_t *)data));
			data         += sizeof(uint64_t);

			// get end point
			uint32_t endl = ntohl(*((uint32_t *)data));
			data         += sizeof(uint32_t);
			if (endl != 8) {
				cf_warning(AS_SINDEX,
						"can only handle 8 byte numerics right now %u", endl);
				goto Cleanup;
			}
			end->u.i64  = __cpu_to_be64(*((uint64_t *)data));
			data       += sizeof(uint64_t);
			if (start->u.i64 > end->u.i64) {
				cf_warning(AS_SINDEX,
                     "Invalid range from %ld to %ld", start->u.i64, end->u.i64);
				goto Cleanup;
			} else if (start->u.i64 == end->u.i64) {
				srange->isrange = FALSE;
			} else {
				srange->isrange = TRUE;
			}
			cf_debug(AS_SINDEX, "Range is equal  %"PRId64", %"PRId64"",
								start->u.i64, end->u.i64);
		} else if (type == AS_PARTICLE_TYPE_STRING) {
			// get start point
			uint32_t startl    = ntohl(*((uint32_t *)data));
			data              += sizeof(uint32_t);
			char* start_binval       = (char *)data;
			data              += startl;
			srange->isrange    = FALSE;

			if ((startl <= 0) || (startl >= AS_SINDEX_MAX_STRING_KSIZE)) {
				cf_warning(AS_SINDEX, "Out of bound query key size %u", startl);
				goto Cleanup;
			}
			uint32_t endl	   = ntohl(*((uint32_t *)data));
			data              += sizeof(uint32_t);
			char * end_binval        = (char *)data;
			if (startl != endl && strncmp(start_binval, end_binval, startl)) {
				cf_warning(AS_SINDEX,
                           "Only Equality Query Supported in Strings %s-%s",
                           start_binval, end_binval);
				goto Cleanup;
			}
			cf_digest_compute(start_binval, startl, &(start->digest));
			cf_debug(AS_SINDEX, "Range is equal %s ,%s",
					 start_binval, end_binval);
		} else if (type == AS_PARTICLE_TYPE_GEOJSON) {
			// get start point
			uint32_t startl = ntohl(*((uint32_t *)data));
			data += sizeof(uint32_t);
			char* start_binval = (char *)data;
			data += startl;

			if ((startl <= 0) || (startl >= AS_SINDEX_MAX_GEOJSON_KSIZE)) {
				cf_warning(AS_SINDEX, "Out of bound query key size %u", startl);
				goto Cleanup;
			}
			uint32_t endl = ntohl(*((uint32_t *)data));
			data += sizeof(uint32_t);
			char * end_binval = (char *)data;
			if (startl != endl && strncmp(start_binval, end_binval, startl)) {
				cf_warning(AS_SINDEX,
						   "Only Geospatial Query Supported on GeoJSON %s-%s",
						   start_binval, end_binval);
				goto Cleanup;
			}

			srange->cellid = 0;
			if (!geo_parse(ns, start_binval, startl,
						   &srange->cellid, &srange->region)) {
				cf_warning(AS_GEO, "failed to parse query GeoJSON");
				goto Cleanup;
			}

			if (srange->cellid && srange->region) {
				geo_region_destroy(srange->region);
				srange->region = NULL;
				cf_warning(AS_GEO, "query geo_parse: both point and region");
				goto Cleanup;
			}

			if (!srange->cellid && !srange->region) {
				cf_warning(AS_GEO, "query geo_parse: neither point nor region");
				goto Cleanup;
			}

			if (srange->cellid) {
				// REGIONS-CONTAINING-POINT QUERY

				uint64_t center[MAX_REGION_LEVELS];
				int numcenters;
				if (!geo_point_centers(ns, srange->cellid, MAX_REGION_LEVELS,
									   center, &numcenters)) {
					cf_warning(AS_GEO, "Query point invalid");
					goto Cleanup;
				}

				// Geospatial queries use multiple srange elements.	 Many
				// of the fields are copied from the first cell because
				// they were filled in above.
				for (int ii = 0; ii < numcenters; ++ii) {
					srange[ii].num_binval = 1;
					srange[ii].isrange = TRUE;
					srange[ii].start.id = srange[0].start.id;
					srange[ii].start.type = srange[0].start.type;
					srange[ii].start.u.i64 = center[ii];
					srange[ii].end.id = srange[0].end.id;
					srange[ii].end.type = srange[0].end.type;
					srange[ii].end.u.i64 = center[ii];
					srange[ii].itype = srange[0].itype;
				}
			} else {
				// POINTS-INSIDE-REGION QUERY

				uint64_t cellmin[MAX_REGION_CELLS];
				uint64_t cellmax[MAX_REGION_CELLS];
				int numcells;
				if (!geo_region_cover(ns, srange->region, MAX_REGION_CELLS,
									  NULL, cellmin, cellmax, &numcells)) {
					cf_warning(AS_GEO, "Query region invalid.");
					goto Cleanup;
				}

				cf_atomic64_incr(&ns->geo_region_query_count);
				cf_atomic64_add(&ns->geo_region_query_cells, numcells);

				// Geospatial queries use multiple srange elements.	 Many
				// of the fields are copied from the first cell because
				// they were filled in above.
				for (int ii = 0; ii < numcells; ++ii) {
					srange[ii].num_binval = 1;
					srange[ii].isrange = TRUE;
					srange[ii].start.id = srange[0].start.id;
					srange[ii].start.type = srange[0].start.type;
					srange[ii].start.u.i64 = cellmin[ii];
					srange[ii].end.id = srange[0].end.id;
					srange[ii].end.type = srange[0].end.type;
					srange[ii].end.u.i64 = cellmax[ii];
					srange[ii].itype = srange[0].itype;
				}
			}
		} else {
			cf_warning(AS_SINDEX, "Only handle String, Numeric and GeoJSON type");
			goto Cleanup;
		}
		srange->num_binval = numrange;
	}
	return AS_SINDEX_OK;

Cleanup:
	return AS_SINDEX_ERR_PARAM;
}

/*
 * Function as_sindex_rangep_from_msg
 *
 * Arguments
 * 		ns     - the namespace on which srange has to be build
 * 		msgp   - the msgp from which sent
 * 		srange - it builds this srange
 *
 * Returns
 * 		AS_SINDEX_OK - On success
 * 		else the return value of as_sindex_range_from_msg
 *
 * Description
 * 		Allocating space for srange and then calling as_sindex_range_from_msg.
 */
int
as_sindex_rangep_from_msg(as_namespace *ns, as_msg *msgp, as_sindex_range **srange)
{
	cf_debug(AS_SINDEX, "as_sindex_rangep_from_msg");

	// NOTE - to support geospatial queries we allocate an array of
	// MAX_REGION_CELLS length.	 Nongeospatial queries use only the
	// first element.  Geospatial queries use one element per region
	// cell, up to MAX_REGION_CELLS.
	*srange         = cf_malloc(sizeof(as_sindex_range) * MAX_REGION_CELLS);
	if (!(*srange)) {
		cf_warning(AS_SINDEX,
                 "Could not Allocate memory for range key. Aborting Query ...");
		return AS_SINDEX_ERR_NO_MEMORY;
	}

	int ret = as_sindex_range_from_msg(ns, msgp, *srange);
	if (AS_SINDEX_OK != ret) {
		as_sindex_range_free(srange);
		*srange = NULL;
		return ret;
	}
	return AS_SINDEX_OK;
}

/*
 * Returns -
 * 		AS_SINDEX_ERR_PARAM
 *		o/w return value from ai_btree_query
 *
 * Notes -
 * 		Client API to do range get from index based on passed in range key, returns
 * 		digest list
 *
 * Synchronization -
 *
 */
int
as_sindex_query(as_sindex *si, as_sindex_range *srange, as_sindex_qctx *qctx)
{
	if ((!si || !srange)) return AS_SINDEX_ERR_PARAM;
	as_sindex_metadata *imd = si->imd;
	SINDEX_RLOCK(&imd->slock);
	SINDEX_RLOCK(&imd->pimd[qctx->pimd_idx].slock);
	int ret = as_sindex__pre_op_assert(si, AS_SINDEX_OP_READ);
	if (AS_SINDEX_OK != ret) {
		SINDEX_UNLOCK(&imd->pimd[qctx->pimd_idx].slock);
		SINDEX_UNLOCK(&imd->slock);
		return ret;
	}
	uint64_t starttime = 0;
	ret = ai_btree_query(imd, srange, qctx);
	as_sindex__process_ret(si, ret, AS_SINDEX_OP_READ, starttime, __LINE__);
	SINDEX_UNLOCK(&imd->pimd[qctx->pimd_idx].slock);
	SINDEX_UNLOCK(&imd->slock);
	return ret;
}
//                                        END -  SINDEX QUERY
// ************************************************************************************************
// ************************************************************************************************
//                                          SBIN UTILITY
void
as_sindex_init_sbin(as_sindex_bin * sbin, as_sindex_op op, as_particle_type type, as_sindex * si)
{
	sbin->si              = si;
	sbin->to_free         = false;
	sbin->num_values      = 0;
	sbin->op              = op;
	sbin->heap_capacity   = 0;
	sbin->type            = type;
	sbin->values          = NULL;
}

int
as_sindex_sbin_free(as_sindex_bin *sbin)
{
	if (sbin->to_free) {
		if (sbin->values) {
			cf_free(sbin->values);
		}
	}
    return AS_SINDEX_OK;
}

int
as_sindex_sbin_freeall(as_sindex_bin *sbin, int numbins)
{
	for (int i = 0; i < numbins; i++)  {
		as_sindex_sbin_free(&sbin[i]);
	}
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex__op_by_sbin(as_namespace *ns, const char *set, int numbins, as_sindex_bin *start_sbin, cf_digest * pkey)
{
	// If numbins == 0 return AS_SINDEX_OK
	// Iterate through sbins
	// 		Reserve the SI.
	// 		Take the read lock on imd
	//		Get a value from sbin
	//			Get the related pimd
	//			Get the pimd write lock
	//			If op is DELETE delete the values from sbin from sindex
	//			If op is INSERT put all the values from bin in sindex.
	//			Release the pimd lock
	//		Release the imd lock.
	//		Release the SI.

	as_sindex_status retval = AS_SINDEX_OK;
	if (!ns || !start_sbin) {
		return AS_SINDEX_ERR;
	}

	// If numbins != 1 return AS_SINDEX_OK
	if (numbins != 1 ) {
		return AS_SINDEX_OK;
	}

	as_sindex * si             = NULL;
	as_sindex_bin * sbin   = NULL;
	as_sindex_metadata * imd   = NULL;
	as_sindex_pmetadata * pimd = NULL;
	as_sindex_op op;
	// Iterate through sbins
	for (int i=0; i<numbins; i++) {
	// 		Reserve the SI.
		sbin = &start_sbin[i];
		si = sbin->si;
		if (!si) {
			cf_warning(AS_SINDEX, "as_sindex_op_by_sbin : si is null in sbin");
			return AS_SINDEX_ERR;
		}
		imd =  si->imd;
		op = sbin->op;
	// 		Take the read lock on imd
		SINDEX_RLOCK(&imd->slock);
		for (int j=0; j<sbin->num_values; j++) {

			int ret = as_sindex__pre_op_assert(si, op);
			if (AS_SINDEX_OK != ret) {
				goto Cleanup;
			}
	//		Get a value from sbin
			void * skey;
			switch (sbin->type) {
			case AS_PARTICLE_TYPE_INTEGER:
			case AS_PARTICLE_TYPE_GEOJSON:
				if (j==0) {
					skey = (void *)&(sbin->value.int_val);
				}
				else {
					skey = (void *)((uint64_t *)(sbin->values) + j);
				}
				break;
			case AS_PARTICLE_TYPE_STRING:
				if (j==0) {
					skey = (void *)&(sbin->value.str_val);
				}
				else {
					skey = (void *)((cf_digest *)(sbin->values) + j);
				}
				break;
			default:
				retval = AS_SINDEX_ERR;
				goto Cleanup;
			}
	//			Get the related pimd
			pimd = &imd->pimd[ai_btree_key_hash(imd, skey)];
			uint64_t starttime = 0;
			if (si->enable_histogram) {
				starttime = cf_getns();
			}

	//			Get the pimd write lock
			SINDEX_WLOCK(&pimd->slock);

	//			If op is DELETE delete the value from sindex
			if (op == AS_SINDEX_OP_DELETE) {
				ret = ai_btree_delete(imd, pimd, skey, pkey);
			}
			else if (op == AS_SINDEX_OP_INSERT) {
	//			If op is INSERT put the value in sindex.
				ret = ai_btree_put(imd, pimd, skey, pkey);
			}

	//			Release the pimd lock
			SINDEX_UNLOCK(&pimd->slock);
			as_sindex__process_ret(si, ret, op, starttime, __LINE__);
		}
		cf_debug(AS_SINDEX, " Secondary Index Op Finish------------- ");

	//		Release the imd lock.
	//		Release the SI.

	}
	Cleanup:
	SINDEX_UNLOCK(&imd->slock);
	return retval;
}
//                                       END - SBIN UTILITY
// ************************************************************************************************
// ************************************************************************************************
//                                          ADD TO SBIN


as_sindex_status
as_sindex_add_sbin_value_in_heap(as_sindex_bin * sbin, void * val)
{
	// Get the size of the data we are going to store
	// If to_free = false, this means this is the first
	// time we are storing value for this sbin to heap
	// Check if there is need to copy the existing data from stack_buf
	// 		init_storage(num_values)
	// 		If num_values != 0
	//			Copy the existing data from stack to heap
	//			reduce the used stack_buf size
	// 		to_free = true;
	// 	Else
	// 		If (num_values == heap_capacity)
	// 			extend the allocation and capacity
	// 	Copy the value to the appropriate position.

	uint32_t   size = 0;
	bool    to_copy = false;
	uint8_t    data_sz = 0;
	void * tmp_value = NULL;
	sbin_value_pool * stack_buf = sbin->stack_buf;

	// Get the size of the data we are going to store
	if (sbin->type == AS_PARTICLE_TYPE_INTEGER ||
		sbin->type == AS_PARTICLE_TYPE_GEOJSON) {
		data_sz = sizeof(uint64_t);
	}
	else if (sbin->type == AS_PARTICLE_TYPE_STRING) {
		data_sz = sizeof(cf_digest);
	}
	else {
		cf_warning(AS_SINDEX, "Bad type of data to index %d", sbin->type);
		return AS_SINDEX_ERR;
	}

	// If to_free = false, this means this is the first
	// time we are storing value for this sbin to heap
	// Check if there is need to copy the existing data from stack_buf
	if (!sbin->to_free) {
		if (sbin->num_values == 0) {
			size = 2;
		}
		else if (sbin->num_values == 1) {
			to_copy = true;
			size = 2;
			tmp_value = &sbin->value;
		}
		else if (sbin->num_values > 1) {
			to_copy = true;
			size = 2 * sbin->num_values;
			tmp_value = sbin->values;
		}
		else {
			cf_warning(AS_SINDEX, "num_values in sbin is less than 0  %"PRIu64"", sbin->num_values);
			return AS_SINDEX_ERR;
		}

		sbin->values  = cf_malloc(data_sz * size);
		if (!sbin->values) {
			cf_warning(AS_SINDEX, "malloc failed");
			return AS_SINDEX_ERR;
		}
		sbin->to_free = true;
		sbin->heap_capacity = size;

	//			Copy the existing data from stack to heap
	//			reduce the used stack_buf size
		if (to_copy) {
			if (!memcpy(sbin->values, tmp_value, data_sz * sbin->num_values)) {
				cf_warning(AS_SINDEX, "memcpy failed");
				return AS_SINDEX_ERR;
			}
			if (sbin->num_values != 1) {
				stack_buf->used_sz -= (sbin->num_values * data_sz);
			}
		}
	}
	else
	{
	// 	Else
	// 		If (num_values == heap_capacity)
	// 			extend the allocation and capacity
		if (sbin->heap_capacity ==  sbin->num_values) {
			sbin->heap_capacity = 2 * sbin->heap_capacity;
			sbin->values = cf_realloc(sbin->values, sbin->heap_capacity * data_sz);
			if (!sbin->values) {
				cf_warning(AS_SINDEX, "Realloc failed for size %d", sbin->heap_capacity * data_sz);
				sbin->heap_capacity = sbin->heap_capacity / 2;
				return AS_SINDEX_ERR;
			}
		}
	}

	// 	Copy the value to the appropriate position.
	if (sbin->type == AS_PARTICLE_TYPE_INTEGER ||
		sbin->type == AS_PARTICLE_TYPE_GEOJSON) {
		if (!memcpy((void *)((uint64_t *)sbin->values + sbin->num_values), (void *)val, data_sz)) {
			cf_warning(AS_SINDEX, "memcpy failed");
			return AS_SINDEX_ERR;
		}
	}
	else if (sbin->type == AS_PARTICLE_TYPE_STRING) {
		if (!memcpy((void *)((cf_digest *)sbin->values + sbin->num_values), (void *)val, data_sz)) {
			cf_warning(AS_SINDEX, "memcpy failed");
			return AS_SINDEX_ERR;
		}
	}
	else {
		cf_warning(AS_SINDEX, "Bad type of data to index %d", sbin->type);
		return AS_SINDEX_ERR;
	}

	sbin->num_values++;
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_add_value_to_sbin(as_sindex_bin * sbin, uint8_t * val)
{
	// If this is the first value coming to the  sbin
	// 		assign the value to the local variable of struct.
	// Else
	// 		If to_free is true or stack_buf is full
	// 			add value to the heap
	// 		else
	// 			If needed copy the values stored in sbin to stack_buf
	// 			add the value to end of stack buf

	int data_sz = 0;
	if (sbin->type == AS_PARTICLE_TYPE_STRING) {
		data_sz = sizeof(cf_digest);
	}
	else if (sbin->type == AS_PARTICLE_TYPE_INTEGER ||
			 sbin->type == AS_PARTICLE_TYPE_GEOJSON) {
		data_sz = sizeof(uint64_t);
	}
	else {
		cf_warning(AS_SINDEX, "sbin type is invalid %d", sbin->type);
		return AS_SINDEX_ERR;
	}

	sbin_value_pool * stack_buf = sbin->stack_buf;
	if (sbin->num_values == 0 ) {
		if (sbin->type == AS_PARTICLE_TYPE_STRING) {
			sbin->value.str_val = *(cf_digest *)val;
		}
		else if (sbin->type == AS_PARTICLE_TYPE_INTEGER ||
				 sbin->type == AS_PARTICLE_TYPE_GEOJSON) {
			sbin->value.int_val = *(int64_t *)val;
		}
		sbin->num_values++;
	}
	else if (sbin->num_values == 1) {
		if ((stack_buf->used_sz + data_sz + data_sz) > AS_SINDEX_VALUESZ_ON_STACK ) {
			if (as_sindex_add_sbin_value_in_heap(sbin, (void *)val)) {
				cf_warning(AS_SINDEX, "Adding value in sbin failed.");
				return AS_SINDEX_ERR;
			}
		}
		else {
			// sbin->values gets initiated here
			sbin->values = stack_buf->value + stack_buf->used_sz;

			if (!memcpy(sbin->values, (void *)&sbin->value, data_sz)) {
				cf_warning(AS_SINDEX, "Memcpy failed");
				return AS_SINDEX_ERR;
			}
			stack_buf->used_sz += data_sz;

			if (!memcpy((void *)((uint8_t *)sbin->values + data_sz * sbin->num_values), (void *)val, data_sz)) {
				cf_warning(AS_SINDEX, "Memcpy failed");
				return AS_SINDEX_ERR;
			}
			sbin->num_values++;
			stack_buf->used_sz += data_sz;
		}
	}
	else if (sbin->num_values > 1) {
		if (sbin->to_free || (stack_buf->used_sz + data_sz ) > AS_SINDEX_VALUESZ_ON_STACK ) {
			if (as_sindex_add_sbin_value_in_heap(sbin, (void *)val)) {
				cf_warning(AS_SINDEX, "Adding value in sbin failed.");
				return AS_SINDEX_ERR;
			}
		}
		else {
			if (!memcpy((void *)((uint8_t *)sbin->values + data_sz * sbin->num_values), (void *)val, data_sz)) {
				cf_warning(AS_SINDEX, "Memcpy failed");
				return AS_SINDEX_ERR;
			}
			sbin->num_values++;
			stack_buf->used_sz += data_sz;
		}
	}
	else {
		cf_warning(AS_SINDEX, "numvalues is coming as negative. Possible memory corruption in sbin.");
		return AS_SINDEX_ERR;
	}
	return AS_SINDEX_OK;
}

as_sindex_status
as_sindex_add_integer_to_sbin(as_sindex_bin * sbin, uint64_t val)
{
	return as_sindex_add_value_to_sbin(sbin, (uint8_t * )&val);
}

as_sindex_status
as_sindex_add_digest_to_sbin(as_sindex_bin * sbin, cf_digest val_dig)
{
	return as_sindex_add_value_to_sbin(sbin, (uint8_t * )&val_dig);
}

as_sindex_status
as_sindex_add_string_to_sbin(as_sindex_bin * sbin, char * val)
{
	if (!val) {
		return AS_SINDEX_ERR;
	}
	// Calculate digest and cal add_digest_to_sbin
	cf_digest val_dig;
	cf_digest_compute(val, strlen(val), &val_dig);
	return as_sindex_add_digest_to_sbin(sbin, val_dig);
}
//                                       END - ADD TO SBIN
// ************************************************************************************************
// ************************************************************************************************
//                                 ADD KEYTYPE FROM BASIC TYPE ASVAL
as_sindex_status
as_sindex_add_long_from_asval(as_val *val, as_sindex_bin *sbin)
{
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (sbin->type != AS_PARTICLE_TYPE_INTEGER) {
		return AS_SINDEX_ERR;
	}

	as_integer *i = as_integer_fromval(val);
	if (!i) {
		return AS_SINDEX_ERR;
	}
	uint64_t int_val = (uint64_t)as_integer_get(i);
	return as_sindex_add_integer_to_sbin(sbin, int_val);
}

as_sindex_status
as_sindex_add_digest_from_asval(as_val *val, as_sindex_bin *sbin)
{
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (sbin->type != AS_PARTICLE_TYPE_STRING) {
		return AS_SINDEX_ERR;
	}

	as_string *s = as_string_fromval(val);
	if (!s) {
		return AS_SINDEX_ERR;
	}
	char * str_val = as_string_get(s);
	return as_sindex_add_string_to_sbin(sbin, str_val);
}

as_sindex_status
as_sindex_add_geo2dsphere_from_as_val(as_val *val, as_sindex_bin *sbin)
{
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (sbin->type != AS_PARTICLE_TYPE_GEOJSON) {
		return AS_SINDEX_ERR;
	}

	as_geojson *g = as_geojson_fromval(val);
	if (!g) {
		return AS_SINDEX_ERR;
	}
	
	const char *s = as_geojson_get(g);
	size_t jsonsz = as_geojson_len(g);
	uint64_t parsed_cellid = 0;
	geo_region_t parsed_region = NULL;

	if (! geo_parse(NULL, s, jsonsz, &parsed_cellid, &parsed_region)) {
		cf_warning(AS_PARTICLE, "geo_parse() failed - unexpected");
		geo_region_destroy(parsed_region);
		return AS_SINDEX_ERR;
	}

	if (parsed_cellid) {
		if (parsed_region) {
			geo_region_destroy(parsed_region);
			cf_warning(AS_PARTICLE, "geo_parse found both point and region");
			return AS_SINDEX_ERR;
		}

		// POINT
		if (as_sindex_add_integer_to_sbin(sbin, parsed_cellid) != AS_SINDEX_OK) {
			cf_warning(AS_PARTICLE, "as_sindex_add_integer_to_sbin() failed - unexpected");
			return AS_SINDEX_ERR;
		}
	}
	else if (parsed_region) {
		// REGION
		int numcells;
		uint64_t outcells[MAX_REGION_CELLS];

		if (! geo_region_cover(NULL, parsed_region, MAX_REGION_CELLS, outcells, NULL, NULL, &numcells)) {
			geo_region_destroy(parsed_region);
			cf_warning(AS_PARTICLE, "geo_region_cover failed");
			return AS_SINDEX_ERR;
		}

		geo_region_destroy(parsed_region);

		int added = 0;
		for (size_t i = 0; i < numcells; i++) {
			if (as_sindex_add_integer_to_sbin(sbin, outcells[i]) == AS_SINDEX_OK) {
				added++;
			}
			else {
				cf_warning(AS_PARTICLE, "as_sindex_add_integer_to_sbin() failed - unexpected");
			}
		}

		if (added == 0 && numcells > 0) {
			return AS_SINDEX_ERR;
		}
	}
	else {
		cf_warning(AS_PARTICLE, "geo_parse found neither point nor region");
		return AS_SINDEX_ERR;
	}

	return AS_SINDEX_OK;
}

typedef as_sindex_status (*as_sindex_add_keytype_from_asval_fn)
(as_val *val, as_sindex_bin * sbin);
static const as_sindex_add_keytype_from_asval_fn
			 as_sindex_add_keytype_from_asval[AS_SINDEX_KEY_TYPE_MAX] = {
	as_sindex_add_long_from_asval,
	as_sindex_add_digest_from_asval,
	as_sindex_add_geo2dsphere_from_as_val,
};

//                             END - ADD KEYTYPE FROM BASIC TYPE ASVAL
// ************************************************************************************************
// ************************************************************************************************
//                                    ADD ASVAL TO SINDEX TYPE
as_sindex_status
as_sindex_add_asval_to_default_sindex(as_val *val, as_sindex_bin * sbin)
{
	return as_sindex_add_keytype_from_asval[as_sindex_key_type_from_pktype(sbin->type)](val, sbin);
}

typedef struct as_sindex_cdt_sbin_s {
	as_particle_type    type;
	as_sindex_bin * sbin;
} as_sindex_cdt_sbin;

static bool as_sindex_add_listvalues_foreach(as_val * element, void * udata)
{
	as_sindex_bin * sbin = (as_sindex_bin *)udata;
	as_sindex_add_keytype_from_asval[as_sindex_key_type_from_pktype(sbin->type)](element, sbin);
	return true;
}

as_sindex_status
as_sindex_add_asval_to_list_sindex(as_val *val, as_sindex_bin * sbin)
{
	// If val type is not AS_LIST
	// 		return AS_SINDEX_ERR
	// Else iterate through all values of list
	// 		If type == AS_PARTICLE_TYPE_STRING
	// 			add all string type values to the sbin
	// 		If type == AS_PARTICLE_TYPE_INTEGER
	// 			add all integer type values to the sbin

	// If val type is not AS_LIST
	// 		return AS_SINDEX_ERR
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (val->type != AS_LIST) {
		return AS_SINDEX_ERR;
	}
	// Else iterate through all elements of map
	as_list * list               = as_list_fromval(val);
	if (as_list_foreach(list, as_sindex_add_listvalues_foreach, sbin)) {
		return AS_SINDEX_OK;
	}
	return AS_SINDEX_ERR;
}

static bool as_sindex_add_mapkeys_foreach(const as_val * key, const as_val * val, void * udata)
{
	as_sindex_bin * sbin = (as_sindex_bin *)udata;
	as_sindex_add_keytype_from_asval[as_sindex_key_type_from_pktype(sbin->type)]((as_val *)key, sbin);
	return true;
}

static bool as_sindex_add_mapvalues_foreach(const as_val * key, const as_val * val, void * udata)
{
	as_sindex_bin * sbin = (as_sindex_bin *)udata;
	as_sindex_add_keytype_from_asval[as_sindex_key_type_from_pktype(sbin->type)]((as_val *)val, sbin);
	return true;
}

as_sindex_status
as_sindex_add_asval_to_mapkeys_sindex(as_val *val, as_sindex_bin * sbin)
{
	// If val type is not AS_MAP
	// 		return AS_SINDEX_ERR
	// 		Defensive check. Should not happen.
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (val->type != AS_MAP) {
		cf_warning(AS_SINDEX, "Unexpected wrong type %d", val->type);
		return AS_SINDEX_ERR;
	}

	// Else iterate through all keys of map
	as_map * map                   = as_map_fromval(val);
	if (as_map_foreach(map, as_sindex_add_mapkeys_foreach, sbin)) {
		return AS_SINDEX_OK;
	}
	return AS_SINDEX_ERR;
}

as_sindex_status
as_sindex_add_asval_to_mapvalues_sindex(as_val *val, as_sindex_bin * sbin)
{
	// If val type is not AS_MAP
	// 		return AS_SINDEX_ERR
	// Else iterate through all values of all keys of the map
	// 		If type == AS_PARTICLE_TYPE_STRING
	// 			add all string type values to the sbin
	// 		If type == AS_PARTICLE_TYPE_INTEGER
	// 			add all integer type values to the sbin

	// If val type is not AS_MAP
	// 		return AS_SINDEX_ERR
	if (!val) {
		return AS_SINDEX_ERR;
	}
	if (val->type != AS_MAP) {
		return AS_SINDEX_ERR;
	}
	// Else iterate through all keys, values of map
	as_map * map                  = as_map_fromval(val);
	if (as_map_foreach(map, as_sindex_add_mapvalues_foreach, sbin)) {
		return AS_SINDEX_OK;
	}
	return AS_SINDEX_ERR;
}

typedef as_sindex_status (*as_sindex_add_asval_to_itype_sindex_fn)
(as_val *val, as_sindex_bin * sbin);
static const as_sindex_add_asval_to_itype_sindex_fn
			 as_sindex_add_asval_to_itype_sindex[AS_SINDEX_ITYPE_MAX] = {
	as_sindex_add_asval_to_default_sindex,
	as_sindex_add_asval_to_list_sindex,
	as_sindex_add_asval_to_mapkeys_sindex,
	as_sindex_add_asval_to_mapvalues_sindex
};
//                                   END - ADD ASVAL TO SINDEX TYPE
// ************************************************************************************************
// ************************************************************************************************
//                                     DIFF FROM ASVAL TO SINDEX

#define AS_SINDEX_SBIN_HASH_SZ 256


static inline uint32_t
as_sindex_hash_fn(void* p_key)
{
	return (uint32_t)cf_hash_fnv(p_key, sizeof(uint32_t));
}


//                                  END - DIFF FROM ASVAL TO SINDEX
// ************************************************************************************************
// ************************************************************************************************
// DIFF FROM BIN TO SINDEX

static bool
as_sindex_bin_add_skey(as_sindex_bin *sbin, const void *skey, as_val_t type)
{
	if (type == AS_STRING) {
		if (as_sindex_add_digest_to_sbin(sbin, *((cf_digest *)skey)) == AS_SINDEX_OK) {
			return true;
		}
	}
	else if (type == AS_INTEGER) {
		if (as_sindex_add_integer_to_sbin(sbin, *((uint64_t *)skey)) == AS_SINDEX_OK) {
			return true;
		}
	}

	return false;
}

static void
packed_val_init_unpacker(const cdt_payload *val, as_unpacker *pk)
{
	pk->buffer = val->ptr;
	pk->length = val->size;
	pk->offset = 0;
}

static bool
packed_val_make_skey(const cdt_payload *val, as_val_t type, void *skey)
{
	as_unpacker pk;
	packed_val_init_unpacker(val, &pk);

	as_val_t packed_type = as_unpack_peek_type(&pk);

	if (packed_type != type) {
		return false;
	}

	if (type == AS_STRING) {
		int32_t size = as_unpack_blob_size(&pk);

		if (size < 0) {
			return false;
		}

		if (pk.buffer[pk.offset++] != AS_BYTES_STRING) {
			return false;
		}

		cf_digest_compute(pk.buffer + pk.offset, pk.length - pk.offset, (cf_digest *)skey);
	}
	else if (type == AS_INTEGER) {
		if (as_unpack_int64(&pk, (int64_t *)skey) < 0) {
			return false;
		}
	}
	else {
		return false;
	}

	return true;
}

static bool
packed_val_add_sbin_or_update_shash(cdt_payload *val, as_sindex_bin *sbin, shash *hash, as_val_t type)
{
	uint8_t skey[sizeof(cf_digest)];

	if (! packed_val_make_skey(val, type, skey)) {
		// packed_vals that aren't of type are ignored.
		return true;
	}

	bool found = false;

	if (shash_get(hash, skey, &found) != SHASH_OK) {
		// Item not in hash, add to sbin.
		return as_sindex_bin_add_skey(sbin, skey, type);
	}
	else {
		// Item is in hash, set it to true.
		found = true;

		if (shash_put(hash, skey, &found) == SHASH_OK) {
			return true;
		}
	}

	return false;
}

static bool
shash_add_packed_val(shash *h, const cdt_payload *val, as_val_t type, bool value)
{
	uint8_t skey[sizeof(cf_digest)];

	if (! packed_val_make_skey(val, type, skey)) {
		// packed_vals that aren't of type are ignored.
		return true;
	}

	if (shash_put(h, skey, &value) != SHASH_OK) {
		return false;
	}

	return true;
}

static int
shash_diff_reduce_fn(void *skey, void *data, void *udata)
{
	bool value = *(bool *)data;
	as_sindex_bin *sbin = (as_sindex_bin *)udata;

	if (! sbin) {
		cf_debug(AS_SINDEX, "SBIN sent as NULL");
		return -1;
	}

	if (! value) {
		// Add in the sbin.
		if (sbin->type == AS_PARTICLE_TYPE_STRING) {
			as_sindex_add_digest_to_sbin(sbin, *(cf_digest*)skey);
		}
		else if (sbin->type == AS_PARTICLE_TYPE_INTEGER) {
			as_sindex_add_integer_to_sbin(sbin, *(uint64_t*)skey);
		}
	}

	return 0;
}

// Find delta list elements and put them into sbins.
// Currently supports only string/integer index types.
static int32_t
as_sindex_sbins_sindex_list_diff_populate(as_sindex_bin *sbins, as_sindex *si, const as_bin *b_old, const as_bin *b_new)
{
	// Algorithm
	//	Add elements of short_list into hash with value = false
	//	Iterate through all the values in the long_list
	//		For all elements of long_list in hash, set value = true
	//		For all elements of long_list not in hash, add to sbin (insert or delete)
	//	Iterate through all the elements of hash
	//		For all elements where value == false, add to sbin (insert or delete)

	as_particle_type type = as_sindex_pktype(si->imd);
	int data_size;
	as_val_t expected_type;

	if (type == AS_PARTICLE_TYPE_STRING) {
		data_size = 20;
		expected_type = AS_STRING;
	}
	else if (type == AS_PARTICLE_TYPE_INTEGER) {
		data_size = 8;
		expected_type = AS_INTEGER;
	}
	else {
		cf_debug(AS_SINDEX, "Invalid data type %d", type);
		return -1;
	}

	cdt_payload old_val;
	cdt_payload new_val;

	as_bin_particle_list_get_packed_val(b_old, &old_val);
	as_bin_particle_list_get_packed_val(b_new, &new_val);

	as_unpacker pk_old;
	as_unpacker pk_new;

	packed_val_init_unpacker(&old_val, &pk_old);
	packed_val_init_unpacker(&new_val, &pk_new);

	int old_list_size = as_unpack_list_header_element_count(&pk_old);
	int new_list_size = as_unpack_list_header_element_count(&pk_new);

	if (old_list_size < 0 || new_list_size < 0) {
		return -1;
	}

	bool old_list_is_short = old_list_size < new_list_size;

	uint32_t short_list_size;
	uint32_t long_list_size;
	as_unpacker *pk_short;
	as_unpacker *pk_long;

	if (old_list_is_short) {
		short_list_size		= old_list_size;
		long_list_size		= new_list_size;
		pk_short			= &pk_old;
		pk_long				= &pk_new;
	}
	else {
		short_list_size		= new_list_size;
		long_list_size		= old_list_size;
		pk_short			= &pk_new;
		pk_long				= &pk_old;
	}

	if (short_list_size == 0) {
		if (long_list_size == 0) {
			return 0;
		}

		as_sindex_init_sbin(sbins, old_list_is_short ? AS_SINDEX_OP_INSERT : AS_SINDEX_OP_DELETE, type, si);

		for (uint32_t i = 0; i < long_list_size; i++) {
			cdt_payload ele;

			ele.ptr = pk_long->buffer + pk_long->offset;
			ele.size = as_unpack_size(pk_long);

			// sizeof(cf_digest) is big enough for all key types we support so far.
			uint8_t skey[sizeof(cf_digest)];

			if (! packed_val_make_skey(&ele, expected_type, skey)) {
				// packed_vals that aren't of type are ignored.
				continue;
			}

			if (! as_sindex_bin_add_skey(sbins, skey, expected_type)) {
				cf_warning(AS_SINDEX, "as_sindex_sbins_sindex_list_diff_populate() as_sindex_bin_add_skey failed");
				as_sindex_sbin_free(sbins);
				return -1;
			}
		}

		return sbins->num_values == 0 ? 0 : 1;
	}

	shash *hash;
	if (shash_create(&hash, as_sindex_hash_fn, data_size, 1, short_list_size, 0) != SHASH_OK) {
		cf_warning(AS_SINDEX, "as_sindex_sbins_sindex_list_diff_populate() failed to create hash");
		return -1;
	}

	// Add elements of shorter list into hash with value = false.
	for (uint32_t i = 0; i < short_list_size; i++) {
		cdt_payload ele = {
				.ptr = pk_short->buffer + pk_short->offset
		};

		int size = as_unpack_size(pk_short);

		if (size < 0) {
			cf_warning(AS_SINDEX, "as_sindex_sbins_sindex_list_diff_populate() list unpack failed");
			shash_destroy(hash);
			return -1;
		}

		ele.size = size;

		if (! shash_add_packed_val(hash, &ele, expected_type, false)) {
			cf_warning(AS_SINDEX, "as_sindex_sbins_sindex_list_diff_populate() hash add failed");
			shash_destroy(hash);
			return -1;
		}
	}

	as_sindex_init_sbin(sbins, old_list_is_short ? AS_SINDEX_OP_INSERT : AS_SINDEX_OP_DELETE, type, si);

	for (uint32_t i = 0; i < long_list_size; i++) {
		cdt_payload ele;

		ele.ptr = pk_long->buffer + pk_long->offset;
		ele.size = as_unpack_size(pk_long);

		if (! packed_val_add_sbin_or_update_shash(&ele, sbins, hash, expected_type)) {
			cf_warning(AS_SINDEX, "as_sindex_sbins_sindex_list_diff_populate() hash update failed");
			as_sindex_sbin_free(sbins);
			shash_destroy(hash);
			return -1;
		}
	}

	// Need to keep track of start for unwinding on error.
	as_sindex_bin *start_sbin = sbins;
	int found = 0;

	if (sbins->num_values > 0) {
		sbins++;
		found++;
	}

	as_sindex_init_sbin(sbins, old_list_is_short ? AS_SINDEX_OP_DELETE : AS_SINDEX_OP_INSERT, type, si);

	// Iterate through all the elements of hash.
	if (shash_reduce(hash, shash_diff_reduce_fn, sbins) != 0) {
		as_sindex_sbin_freeall(start_sbin, found + 1);
		shash_destroy(hash);
		return -1;
	}

	if (sbins->num_values > 0) {
		found++;
	}

	shash_destroy(hash);

	return found;
}

void
as_sindex_sbins_debug_print(as_sindex_bin *sbins, uint32_t count)
{
	cf_warning( AS_SINDEX, "as_sindex_sbins_list_update_diff() found=%d", count);
	for (uint32_t i = 0; i < count; i++) {
		as_sindex_bin *p = sbins + i;

		cf_warning( AS_SINDEX, "  %d: values= %"PRIu64" type=%d op=%d",
				i, p->num_values, p->type, p->op);

		if (p->type == AS_PARTICLE_TYPE_INTEGER) {
			int64_t *values = (int64_t *)p->values;

			if (p->num_values == 1) {
				cf_warning( AS_SINDEX, "    %ld", p->value.int_val);
			}
			else {
				for (uint64_t j = 0; j < p->num_values; j++) {
					cf_warning( AS_SINDEX, "     %"PRIu64":  %"PRId64"", j, values[j]);
				}
			}
		}
	}
}

// Assumes b_old and b_new are AS_PARTICLE_TYPE_LIST bins.
// Assumes b_old and b_new have the same id.
static int32_t
as_sindex_sbins_list_diff_populate(as_sindex_bin *sbins, as_namespace *ns, const char *set_name, const as_bin *b_old, const as_bin *b_new)
{
	uint16_t id = b_new->id;

	if (! as_sindex_binid_has_sindex(ns, id)) {
		return 0;
	}

	cf_ll *simatch_ll = NULL;
	as_sindex__simatch_list_by_set_binid(ns, set_name, id, &simatch_ll);

	if (! simatch_ll) {
		return 0;
	}

	uint32_t populated = 0;

	for (cf_ll_element *ele = cf_ll_get_head(simatch_ll); ele; ele = ele->next) {
		sindex_set_binid_hash_ele *si_ele = (sindex_set_binid_hash_ele *)ele;
		int simatch = si_ele->simatch;
		as_sindex *si = &ns->sindex[simatch];

		if (! as_sindex_isactive(si)) {
			ele = ele->next;
			continue;
		}

		int32_t delta = as_sindex_sbins_sindex_list_diff_populate(&sbins[populated], si, b_old, b_new);

		if (delta < 0) {
			return -1;
		}

		populated += delta;
	}

	return populated;
}

uint32_t
as_sindex_sbins_populate(as_sindex_bin *sbins, as_namespace *ns, const char *set_name, const as_bin *b_old, const as_bin *b_new)
{
	if (as_bin_get_particle_type(b_old) == AS_PARTICLE_TYPE_LIST && as_bin_get_particle_type(b_new) == AS_PARTICLE_TYPE_LIST) {
		int32_t ret = as_sindex_sbins_list_diff_populate(sbins, ns, set_name, b_old, b_new);

		if (ret >= 0) {
			return (uint32_t)ret;
		}
	}

	uint32_t populated = 0;

	// TODO - might want an optimization that detects the (rare) case when a
	// particle was rewritten with the exact old value.
	populated += as_sindex_sbins_from_bin(ns, set_name, b_old, &sbins[populated], AS_SINDEX_OP_DELETE);
	populated += as_sindex_sbins_from_bin(ns, set_name, b_new, &sbins[populated], AS_SINDEX_OP_INSERT);

	return populated;
}
// DIFF FROM BIN TO SINDEX
// ************************************************************************************************
// ************************************************************************************************
//                                     SBIN INTERFACE FUNCTIONS
int
as_sindex_sbin_from_sindex(as_sindex * si, const as_bin *b, as_sindex_bin * sbin, as_val ** cdt_asval)
{
	as_sindex_metadata * imd    = si->imd;
	as_particle_type imd_btype  = as_sindex_pktype(imd);
	as_val * cdt_val            = * cdt_asval;
	uint32_t  valsz             = 0;
	int sindex_found            = 0;
	as_particle_type bin_type   = 0;
	bool found = false;

	bin_type = as_bin_get_particle_type(b);

	//		Prepare si
	// 		If path_length == 0
	if (imd->path_length == 0) {
		// 			If itype == AS_SINDEX_ITYPE_DEFAULT and bin_type == STRING OR INTEGER
		// 				Add the value to the sbin.
		if (imd->itype == AS_SINDEX_ITYPE_DEFAULT && bin_type == imd_btype) {
			if (bin_type == AS_PARTICLE_TYPE_INTEGER) {
				found = true;
				sbin->value.int_val = as_bin_particle_integer_value(b);

				if (as_sindex_add_integer_to_sbin(sbin, (uint64_t)sbin->value.int_val) == AS_SINDEX_OK) {
					if (sbin->num_values) {
						sindex_found++;
					}
				}
			}
			else if (bin_type == AS_PARTICLE_TYPE_STRING) {
				found = true;
				char* bin_val;
				valsz = as_bin_particle_string_ptr(b, &bin_val);

				if (valsz < 0 || valsz > AS_SINDEX_MAX_STRING_KSIZE) {
					cf_warning( AS_SINDEX, "sindex key size out of bounds %d ", valsz);
				}
				else {
					cf_digest buf_dig;
					cf_digest_compute(bin_val, valsz, &buf_dig);

					if (as_sindex_add_digest_to_sbin(sbin, buf_dig) == AS_SINDEX_OK) {
						if (sbin->num_values) {
							sindex_found++;
						}
					}
				}
			}
			else if (bin_type == AS_PARTICLE_TYPE_GEOJSON) {
				// GeoJSON is like AS_PARTICLE_TYPE_STRING when
				// reading the value and AS_PARTICLE_TYPE_INTEGER for
				// adding the result to the index.
				found = true;
				bool added = false;
				uint64_t * cells;
				size_t ncells = as_bin_particle_geojson_cellids(b, &cells);
				for (size_t ndx = 0; ndx < ncells; ++ndx) {
					if (as_sindex_add_integer_to_sbin(sbin, cells[ndx]) == AS_SINDEX_OK) {
						added = true;
					}
				}
				if (added && sbin->num_values) {
					sindex_found++;
				}
			}
		}
	}
	// 		Else if path_length > 0 OR type == MAP or LIST
	// 			Deserialize the bin if have not deserialized it yet.
	//			Extract as_val from path within the bin.
	//			Add the values to the sbin.
	if (!found) {
		if (bin_type == AS_PARTICLE_TYPE_MAP || bin_type == AS_PARTICLE_TYPE_LIST) {
			if (! cdt_val) {
				cdt_val = as_bin_particle_to_asval(b);
			}
			as_val * res_val   = as_sindex_extract_val_from_path(imd, cdt_val);
			if (!res_val) {
				goto END;
			}
			if (as_sindex_add_asval_to_itype_sindex[imd->itype](res_val, sbin) == AS_SINDEX_OK) {
				if (sbin->num_values) {
					sindex_found++;
				}
			}
		}
	}
END:
	*cdt_asval = cdt_val;
	return sindex_found;
}

// Returns the number of sindex found
// TODO - deprecate and conflate body with as_sindex_sbins_from_bin() below.
int
as_sindex_sbins_from_bin_buf(as_namespace *ns, const char *set, const as_bin *b, as_sindex_bin * start_sbin,
					as_sindex_op op)
{
	// Check the sindex bit array.
	// If there is not sindex present on this bin return 0
	// Get the simatch_ll from set_binid_hash
	// If simatch_ll is NULL return 0
	// Iterate through simatch_ll
	// 		If path_length == 0
	// 			If itype == AS_SINDEX_ITYPE_DEFAULT and bin_type == STRING OR INTEGER
	// 				Add the value to the sbin.
	//			If itype == AS_SINDEX_ITYPE_MAP or AS_SINDEX_ITYPE_INVMAP and type = MAP
	//	 			Deserialize the bin if have not deserialized it yet.
	//				Extract as_val from path within the bin
	//				Add them to the sbin.
	// 			If itype == AS_SINDEX_ITYPE_LIST and type = LIST
	//	 			Deserialize the bin if have not deserialized it yet.
	//				Extract as_val from path within the bin.
	//				Add the values to the sbin.
	// 		Else if path_length > 0 and type == MAP or LIST
	// 			Deserialize the bin if have not deserialized it yet.
	//			Extract as_val from path within the bin.
	//			Add the values to the sbin.
	// Return the number of sbins found.

	int sindex_found = 0;
	if (!b) {
		cf_warning(AS_SINDEX, "Null Bin Passed, No sbin created");
		return sindex_found;
	}
	if (!ns) {
		cf_warning(AS_SINDEX, "NULL Namespace Passed");
		return sindex_found;
	}
	if (!as_bin_inuse(b)) {
		return sindex_found;
	}

	// Check the sindex bit array.
	// If there is not sindex present on this bin return 0
	if (!as_sindex_binid_has_sindex(ns, b->id) ) {
		return sindex_found;
	}

	// Get the simatch_ll from set_binid_hash
	cf_ll * simatch_ll  = NULL;
	as_sindex__simatch_list_by_set_binid(ns, set, b->id, &simatch_ll);

	// If simatch_ll is NULL return 0
	if (!simatch_ll) {
		return sindex_found;
	}

	// Iterate through simatch_ll
	cf_ll_element             * ele    = cf_ll_get_head(simatch_ll);
	sindex_set_binid_hash_ele * si_ele = NULL;
	int                        simatch = -1;
	as_sindex                 * si     = NULL;
	as_val                   * cdt_val = NULL;
	int                   sbins_in_si  = 0;
	while (ele) {
		si_ele                = (sindex_set_binid_hash_ele *) ele;
		simatch               = si_ele->simatch;
		si                    = &ns->sindex[simatch];
		if (!as_sindex_isactive(si)) {
			ele = ele->next;
			continue;
		}
		as_sindex_init_sbin(&start_sbin[sindex_found], op,  as_sindex_pktype(si->imd), si);
		uint64_t s_time = cf_getns();
		sbins_in_si          = as_sindex_sbin_from_sindex(si, b, &start_sbin[sindex_found], &cdt_val);
		if (sbins_in_si == 1) {
			sindex_found += sbins_in_si;
			// sbin free will happen once sbin is updated in sindex tree
			SINDEX_HIST_INSERT_DATA_POINT(si, si_prep_hist, s_time);
		}
		else {
			as_sindex_sbin_free(&start_sbin[sindex_found]);
			if (sbins_in_si) {
				cf_warning(AS_SINDEX, "sbins found in si is neither 1 nor 0. It is %d", sbins_in_si);
			}
		}
		ele                   = ele->next;
	}

	// FREE as_val
	if (cdt_val) {
		as_val_destroy(cdt_val);
	}
	// Return the number of sbin found.
	return sindex_found;
}

int
as_sindex_sbins_from_bin(as_namespace *ns, const char *set, const as_bin *b, as_sindex_bin * start_sbin, as_sindex_op op)
{
	return as_sindex_sbins_from_bin_buf(ns, set, b, start_sbin, op);
}

/*
 * returns number of sbins found.
 */
int
as_sindex_sbins_from_rd(as_storage_rd *rd, uint16_t from_bin, uint16_t to_bin, as_sindex_bin sbins[], as_sindex_op op)
{
	uint16_t count  = 0;
	for (uint16_t i = from_bin; i < to_bin; i++) {
		as_bin *b   = &rd->bins[i];
		count      += as_sindex_sbins_from_bin(rd->ns, as_index_get_set_name(rd->r, rd->ns), b, &sbins[count], op);
	}
	return count;
}

// Needs comments
int
as_sindex_update_by_sbin(as_namespace *ns, const char *set, as_sindex_bin *start_sbin, int num_sbins, cf_digest * pkey)
{
	cf_debug(AS_SINDEX, "as_sindex_update_by_sbin");

	// Need to address sbins which have OP as AS_SINDEX_OP_DELETE before the ones which have
	// OP as AS_SINDEX_OP_INSERT. This is because same secondary index key can exist in sbins
	// with different OPs
	int sindex_ret = AS_SINDEX_OK;
	for (int i=0; i<num_sbins; i++) {
		if (start_sbin[i].op == AS_SINDEX_OP_DELETE) {
			sindex_ret = as_sindex__op_by_sbin(ns, set, 1, &start_sbin[i], pkey);
		}
	}
	for (int i=0; i<num_sbins; i++) {
		if (start_sbin[i].op == AS_SINDEX_OP_INSERT) {
			sindex_ret = as_sindex__op_by_sbin(ns, set, 1, &start_sbin[i], pkey);
		}
	}
	return sindex_ret;
}
//                                 END - SBIN INTERFACE FUNCTIONS
// ************************************************************************************************
// ************************************************************************************************
//                                      PUT RD IN SINDEX
// Takes a record and tries to populate it in every sindex present in the namespace.
void
as_sindex_putall_rd(as_namespace *ns, as_storage_rd *rd)
{
	int count = 0;
	int valid = 0;

	while (count < AS_SINDEX_MAX && valid < ns->sindex_cnt) {
		as_sindex *si = &ns->sindex[count];
		if (!as_sindex_put_rd(si, rd)) {
			valid++;
		}
		count++;
	}
}

as_sindex_status
as_sindex_put_rd(as_sindex *si, as_storage_rd *rd)
{
	if (!si) {
		cf_warning(AS_SINDEX, "SI is null in as_sindex_put_rd");
		return AS_SINDEX_ERR;
	}

	// Proceed only if sindex is active
	SINDEX_GRLOCK();
	if (!as_sindex_isactive(si)) {
		SINDEX_GUNLOCK();
		return AS_SINDEX_ERR;
	}

	as_sindex_metadata *imd = si->imd;
	// Validate Set name. Other function do this check while
	// performing searching for simatch.
	const char *setname = NULL;
	if (as_index_has_set(rd->r)) {
		setname = as_index_get_set_name(rd->r, si->ns);
	}
	SINDEX_RLOCK(&imd->slock);
	if (!as_sindex__setname_match(imd, setname)) {
		SINDEX_UNLOCK(&imd->slock);
		SINDEX_GUNLOCK();
		return AS_SINDEX_OK;
	}

	SINDEX_UNLOCK(&imd->slock);

	// collect sbins
	SINDEX_BINS_SETUP(sbins, 1);

	int sbins_populated = 0;
	as_val * cdt_val = NULL;

	as_bin *b = as_bin_get(rd, imd->bname);

	if (!b) {
		SINDEX_GUNLOCK();
		return AS_SINDEX_OK;
	}

	as_sindex_init_sbin(&sbins[sbins_populated], AS_SINDEX_OP_INSERT,
												as_sindex_pktype(si->imd), si);
	sbins_populated = as_sindex_sbin_from_sindex(si, b, &sbins[sbins_populated], &cdt_val);

	// Only 1 sbin should be populated here.
	// If populated should be freed after sindex update
	if (sbins_populated != 1) {
		as_sindex_sbin_free(&sbins[sbins_populated]);
		if (sbins_populated) {
			cf_warning(AS_SINDEX, "Number of sbins found for 1 sindex is neither 1 nor 0. It is %d",
					sbins_populated);
		}
	}
	SINDEX_GUNLOCK();

	if (cdt_val) {
		as_val_destroy(cdt_val);
	}

	if (sbins_populated) {
		as_sindex_update_by_sbin(rd->ns, setname, sbins, sbins_populated, &rd->keyd);
		as_sindex_sbin_freeall(sbins, sbins_populated);
	}

	return AS_SINDEX_OK;
}
//                                    END - PUT RD IN SINDEX
// ************************************************************************************************
// ************************************************************************************************
//                                      MEMORY ACCOUNTING
/*
 * Internal function API for tracking sindex memory usage. This get called
 * from inside Aerospike Index.
 *
 * TODO: Make accounting subsystem cache friendly. At high speed it
 *       cache misses it causes starts to matter
 * TODO: This shows up in perf output on running prformance run
 *
 * Reserve locally first then globally
 */
bool
as_sindex_reserve_data_memory(as_sindex_metadata *imd, uint64_t bytes)
{
	if (!bytes) {
		return true;
	}

	if (!imd) {
		cf_warning(AS_SINDEX, "imd is null");
		return false;
	}

	as_namespace *ns = imd->si->ns;
	bool g_reserved  = false;
	bool ns_reserved = false;
	bool si_reserved = false;
	uint64_t val     = 0;

	// Global sindex memory reservation
	val = cf_atomic64_add(&g_config.sindex_data_memory_used, bytes);
	g_reserved = true;
	if (val > g_config.sindex_data_max_memory) {
		goto FAIL;
	}
	
	// Namespace sindex memory reservation
	val = cf_atomic64_add(&ns->sindex_data_memory_used, bytes);
	ns_reserved = true;
	if (val > ns->sindex_data_max_memory) {
		goto FAIL;
	}

	// Secondary Index memory reservation
	val = cf_atomic64_add(&imd->si->stats.mem_used, bytes);
	si_reserved = true;
	if (val > imd->si->config.data_max_memory) {
		goto FAIL;
	}
	return true;

FAIL:
	if (ns_reserved) {
		cf_atomic64_sub(&ns->sindex_data_memory_used, bytes);
	}
	if (g_reserved)  {
		cf_atomic64_sub(&g_config.sindex_data_memory_used, bytes);
	}
	if (si_reserved) {
		cf_atomic64_sub(&imd->si->stats.mem_used, bytes);
	}
	cf_warning(AS_SINDEX, "Sindex memory cap hit for index %s while reserving %ld bytes",
			imd->iname, bytes);
	return false;
}

// release locally first then globally
bool
as_sindex_release_data_memory(as_sindex_metadata *imd, uint64_t bytes)
{
	if (!bytes) {
		return true;
	}

	as_namespace *ns = imd->si->ns;

	uint64_t g_mem = cf_atomic64_get(g_config.sindex_data_memory_used);
	uint64_t ns_mem = cf_atomic64_get(ns->sindex_data_memory_used);
	uint64_t si_mem = cf_atomic64_get(imd->si->stats.mem_used);
	
	if (g_mem < bytes || ns_mem < bytes || si_mem < bytes) {
		cf_warning(AS_SINDEX, "Sindex memory usage accounting is corrupted. [%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"]",
				g_mem, ns_mem, si_mem, bytes);
		return false;
	}
	cf_atomic64_sub(&ns->sindex_data_memory_used, bytes);
	cf_atomic64_sub(&g_config.sindex_data_memory_used, bytes);
	cf_atomic64_sub(&imd->si->stats.mem_used, bytes);
	return true;
}

uint64_t
as_sindex_get_ns_memory_used(as_namespace *ns)
{
	if (as_sindex_ns_has_sindex(ns)) {
		return cf_atomic64_get(ns->sindex_data_memory_used);
	}
	return 0;
}
//                                     END - MEMORY ACCOUNTING
// ************************************************************************************************
// ************************************************************************************************
//                                           SMD CALLBACKS
/*
 *                +------------------+
 *  client -->    |  Secondary Index |
 *                +------------------+
 *                     /|\
 *                      | 4 accept
 *                  +----------+   2
 *                  |          |<-------   +------------------+ 1 request
 *                  | SMD      | 3 merge   |  Secondary Index | <------------|
 *                  |          |<------->  |                  | 5 response   | CLIENT
 *                  |          | 4 accept  |                  | ------------>|
 *                  |          |-------->  +------------------+
 *                  +----------+
 *                     |   4 accept
 *                    \|/
 *                +------------------+
 *  client -->    |  Secondary Index |
 *                +------------------+
 *
 *
 *  System Metadta module sits in the middle of multiple secondary index
 *  module on multiple nodes. The changes which eventually are made to the
 *  secondary index are always triggerred from SMD. Here is the flow.
 *
 *  Step1: Client send (could possibly be secondary index thread) triggers
 *         create / delete / update related to secondary index metadata.
 *
 *  Step2: The request passed through secondary index module (may be few
 *         node specific info is added on the way) to the SMD.
 *
 *  Step3: SMD send out the request to the paxos master.
 *
 *  Step4: Paxos master request the relevant metadata info from all the
 *         nodes in the cluster once it has all the data... [SMD always
 *         stores copy of the data, it is stored when the first time
 *         create happens]..it call secondary index merge callback
 *         function. The function is responsible for resolving the winning
 *         version ...
 *
 *  Step5: Once winning version is decided for all the registered module
 *         the changes are sent to all the node.
 *
 *  Step6: At each node accept_fn is called for each module. Which triggers
 *         the call to the secondary index create/delete/update functions
 *         which would be used to in-memory operation and make it available
 *         for the system.
 *
 *  There are two types of operations which look at the secondary index
 *  operations.
 *
 *  a) Normal operation .. they all look a the in-memory structure and
 *     data which is in sindex and ai_btree layer.
 *
 *  b) Other part which do DDL operation like which work through the SMD
 *     layer. Multiple operation happening from the multiple nodes which
 *     come through this layer. The synchronization is responsible of
 *     SMD layer. The part sindex / ai_btree code is responsible is to
 *     make sure when the call from the SMD comes there is proper sync
 *     between this and operation in section a
 *
 */

// Global flag to signal that all secondary index SMD is restored.
bool g_sindex_smd_restored = false;
/*
 * Description: This cb function is called by paxos master, before doing the
 *              In the case of AS_SMD_SET_ACTION
 *              1) existence of index with the given index name.
 *              2) Whether the bin already has a index
 *              In case of AS_SMD_DELETE_ACTION
 *              1) the existence of index with the given name
 * Parameters:
 * 			   module -- module name (SINDEX_MODULE)
 * 			   item   -- action item that paxos master has received
 * 			   udata  -- user data for the callback
 *
 * Returns:
 * 	In case of AS_SMD_SET_ACTION:
 * 		AS_SIDNEX_ERR_INDEX_FOUND  - if index with the given name exists or bin
 * 									  already has an index
 * 		AS_SINDEX_OK			    - Otherwise
 * 	In case of AS_SMD_DELETE_ACTION
 * 		AS_SINDEX_ERR_NOTFOUND      - Index does not exist with the given index name
 * 		AS_SINDEX_OK				- Otherwise
 *
 * 	Synchronization
 * 		This function takes SINDEX GLOBAL WRITE LOCK and releasese it for checking deletion
 * 		operation.
 */
int
as_sindex_smd_can_accept_cb(char *module, as_smd_item_t *item, void *udata)
{
	as_sindex_metadata imd;
	memset((void *)&imd, 0, sizeof(imd));

	char         * params = NULL;
	as_namespace * ns     = NULL;
	int retval            = AS_SINDEX_ERR;

	switch (item->action) {
		case AS_SMD_ACTION_SET:
			{
				params = item->value;
				bool smd_op = false;
				if (as_info_parse_params_to_sindex_imd(params, &imd, NULL, true, &smd_op, "SINDEX CREATE in SMD")){
					goto ERROR;
				}
				ns     = as_namespace_get_byname(imd.ns_name);
				retval = as_sindex_create_check_params(ns, &imd);

				if(retval != AS_SINDEX_OK){
					cf_warning(AS_SINDEX, "Callback from paxos master for validation failed with error code %d", retval);
					goto ERROR;
				}
				break;
			}
		case AS_SMD_ACTION_DELETE:
			{
				char * key_dup = cf_strdup(item->key);
				// Get ns name
				// Using strtok_r instead of strtok due to MT environment.
				char * saveptr = NULL;
				char * ns_tmpname    = strtok_r(key_dup, ":", &saveptr);
				if (!ns_tmpname) {
					cf_debug(AS_SINDEX, "Failed to extract namspace name from SMD delete item value");
					retval = AS_SINDEX_ERR;
					cf_free(key_dup);
					goto ERROR;
				}
				else {
					cf_debug(AS_SINDEX, "Extracted namespace name from SMD delete item value -> %s", ns_tmpname);
				}

				// Get index name
				char * i_tmpname      = strtok_r(NULL, ":", &saveptr);
				if (!i_tmpname) {
					cf_debug(AS_SINDEX, "Failed to extract index name from SMD delete item value");
					retval = AS_SINDEX_ERR;
					cf_free(key_dup);
					goto ERROR;
				}
				else {
					cf_debug(AS_SINDEX, "Extracted index name from SMD delete item value -> %s", i_tmpname);
				}

				imd.ns_name = cf_strdup(ns_tmpname);
				imd.iname   = cf_strdup(i_tmpname);
				ns          = as_namespace_get_byname(imd.ns_name);
				if (as_sindex_lookup_by_iname(ns, imd.iname, AS_SINDEX_LOOKUP_FLAG_NORESERVE | AS_SINDEX_LOOKUP_FLAG_ISACTIVE)) {
					retval = AS_SINDEX_OK;
				}
				else {
					retval = AS_SINDEX_ERR_NOTFOUND;
				}
				cf_free(key_dup);
				break;
			}
	}

ERROR:
	as_sindex_imd_free(&imd);
	return retval;
}

int
as_sindex_cfg_var_hash_reduce_fn(void *key, void *data, void *udata)
{
	// Parse through the entire si_cfg_array, do an shash_delete on all the valid entries
	// How do we know if its a valid-entry ? valid-entries get marked by the valid_flag in
	// the process of doing as_sindex_create() called by smd.
	// display a warning for those that are not valid and finally, free the entire structure

	as_sindex_config_var *si_cfg_var = (as_sindex_config_var *)data;

	if (! si_cfg_var->conf_valid_flag) {
		cf_warning(AS_SINDEX, "No secondary index %s found. Configuration stanza for %s ignored.", si_cfg_var->name, si_cfg_var->name);
	}

	return 0;
}

/*
 * This function is called when the SMD has resolved the correct state of
 * metadata. This function needs to, based on the value, looks at the current
 * state of the index and trigger requests to secondary index to do the
 * needful. At the start of time there is nothing in sindex and this code
 * comes and setup indexes
 *
 * Expectation. SMD is responsible for persisting data and communicating back
 *              to sindex layer to create in-memory structures
 *
 *
 * Description: To perform sindex operations(ADD,MODIFY,DELETE), through SMD
 * 				This function called on every node, after paxos master decides
 * 				the final version of the sindex to be created. This is the final
 *				version and the only allowed version in the sindex.Operations coming
 *				to this function are least expected to fail, ideally they should
 *				never fail.
 *
 * Parameters:
 * 		module:             SINDEX_MODULE
 * 		as_smd_item_list_t: list of action items, to be performed on sindex.
 * 		udata:              ??
 *
 * Returns:
 * 		always 0
 *
 * Synchronization:
 * 		underlying secondary index all needs to take corresponding lock and
 * 		SMD is today single threaded no sync needed there
 */
int
as_sindex_smd_accept_cb(char *module, as_smd_item_list_t *items, void *udata, uint32_t accept_opt)
{
	if (accept_opt & AS_SMD_ACCEPT_OPT_CREATE) {
		cf_debug(AS_SINDEX, "all secondary index SMD restored");
		g_sindex_smd_restored = true;
		return 0;
	}

	as_sindex_metadata imd;
	char         * params = NULL;
	as_namespace * ns     = NULL;

	for (int i = 0; i < items->num_items; i++) {
		memset((void *)&imd, 0, sizeof(imd));

		params = items->item[i]->value;
		switch (items->item[i]->action) {
			// TODO: Better handling of failure of the action items list
			case AS_SMD_ACTION_SET:
			{
				bool smd_op = false;
				if (as_info_parse_params_to_sindex_imd(params, &imd, NULL, true, &smd_op, "SINDEX CREATE in SMD")) {
					cf_info(AS_SINDEX,"Parsing the index metadata for index creation failed");
					break;
				}

				ns         = as_namespace_get_byname(imd.ns_name);
				if (as_sindex_exists_by_defn(ns, &imd)) {
					cf_detail(AS_SINDEX, "Index with the same index defn already exists.");
					// Fail quietly for duplicate sindex requests
					continue;
				}
				// Pessimistic --Checking again. This check was already done by the paxos master.
				int retval = as_sindex_create_check_params(ns, &imd);
				if (retval != AS_SINDEX_OK) {
						// Two possible cases for reaching here
						// 1. It is possible that secondary index is not active hence defn check
						//    fails but params check pick up sindex in destroy state as well.
						// 2. SMD thread is single threaded ... not sure how can above definition
						//    check fail but params check pass. But just in case it does bail out
						//    destroy and recreate (Accept the final version). think !!!!
						cf_warning(AS_SINDEX, "Index creation failed. Error %d Dropping the index due to cluster state change", retval);
						imd.post_op = 1; // This will lead to sindex recreation
						as_sindex_destroy(ns, &imd);
				}
				else {
					retval = as_sindex_create(ns, &imd, true);
				}
				break;
			}
			case AS_SMD_ACTION_DELETE:
			{
				char * key_dup = cf_strdup(items->item[i]->key);

				char * saveptr = NULL;
				// Using strtok_r instead of strtok due to MT environment.
				// Get ns name
				char * ns_tmpname    = strtok_r(key_dup, ":", &saveptr);
				if (!ns_tmpname) {
					cf_debug(AS_SINDEX, "Failed to extract namspace name from SMD delete item value");
					cf_free(key_dup);
					break;
				}
				else {
					cf_debug(AS_SINDEX, "Extracted namespace name from SMD delete item value -> %s", ns_tmpname);
				}

				// Get index name
				char * i_tmpname      = strtok_r(NULL, ":", &saveptr);
				if (!i_tmpname) {
					cf_debug(AS_SINDEX, "Failed to extract index name from SMD delete item value");
					cf_free(key_dup);
					break;
				}
				else {
					cf_debug(AS_SINDEX, "Extracted index name from SMD delete item value -> %s", i_tmpname);
				}

				imd.ns_name = cf_strdup(ns_tmpname);
				imd.iname   = cf_strdup(i_tmpname);
				ns          = as_namespace_get_byname(imd.ns_name);
				as_sindex_destroy(ns, &imd);
				cf_free(key_dup);
				break;
			}
		}

		as_sindex_imd_free(&imd);
	}

	// Check if the incoming operation is merge. If it's merge
	// After merge resolution of cluster, drop the local sindex definitions which are not part
	// of the paxos principal's sindex definition.
	if (accept_opt & AS_SMD_ACCEPT_OPT_MERGE) {
		for (int k = 0; k < g_config.n_namespaces; k++) { // for each namespace
			as_namespace *local_ns = g_config.namespaces[k];

			if (local_ns->sindex_cnt > 0) {
				as_sindex *del_list[AS_SINDEX_MAX];
				int        del_cnt = 0;
				SINDEX_GRLOCK();

				// Create List of Index to be Deleted
				for (int i = 0; i < AS_SINDEX_MAX; i++) {
					as_sindex *si = &local_ns->sindex[i];
					if (si && si->imd && as_sindex_isactive(si)) {
						int found     = 0;
						SINDEX_RLOCK(&si->imd->slock);
						for (int j = 0; j < items->num_items; j++) {
							char key[256];
							sprintf(key, "%s:%s", si->imd->ns_name, si->imd->iname);
							cf_detail(AS_SINDEX,"Item key %s \n", items->item[j]->key);

							if (strcmp(key, items->item[j]->key) == 0) {
								found = 1;
								cf_detail(AS_SINDEX, "Item found in merge list %s \n", si->imd->iname);
								break;
							}
						}
						SINDEX_UNLOCK(&si->imd->slock);

						if (found == 0) { // Was not found in the merged list from paxos principal
							AS_SINDEX_RESERVE(si);
							del_list[del_cnt] = si;
							del_cnt++;
						}
					}
				}

				SINDEX_GUNLOCK();

				// Delete Index
				for (int i = 0 ; i < del_cnt; i++) {
					if (del_list[i]) {
						as_sindex_destroy(local_ns, del_list[i]->imd);
						AS_SINDEX_RELEASE(del_list[i]);
						del_list[i] = NULL;
					}
				}
			}
		}
	}

	return(0);
}
//                                     END - SMD CALLBACKS
// ************************************************************************************************
// ************************************************************************************************
//                                         SINDEX TICKER
// Sindex ticker start
void
as_sindex_ticker_start(as_namespace * ns, as_sindex * si)
{
	cf_info(AS_SINDEX, "Sindex-ticker start: ns=%s si=%s job=%s", ns->name ? ns->name : "<all>",
			si ? si->imd->iname : "<all>", si ? "SINDEX_POPULATE" : "SINDEX_POPULATEALL");

}
// Sindex ticker
void
as_sindex_ticker(as_namespace * ns, as_sindex * si, uint64_t n_obj_scanned, uint64_t start_time)
{
	const uint64_t sindex_ticker_obj_count = 500000;

	if (n_obj_scanned % sindex_ticker_obj_count == 0 && n_obj_scanned != 0) {
		// Ticker can be dumped from here, we'll be in this place for both
		// sindex populate and populate-all.
		// si memory gets set from as_sindex_reserve_data_memory() which in turn gets set from :
		// ai_btree_put() <- for every single sindex insertion (boot-time/dynamic)
		// as_sindex_create() : for dynamic si creation, cluster change, smd on boot-up.

		uint64_t si_memory   = 0;
		char   * si_name     = NULL;

		if (si) {
			si_memory        = cf_atomic64_get(si->stats.mem_used);
			si_name          = si->imd->iname;
		}
		else {
			si_memory        = (uint64_t)cf_atomic64_get(ns->sindex_data_memory_used);
			si_name          = "<all>";
		}

		uint64_t n_objects       = (uint64_t)cf_atomic_int_get(ns->n_objects);
		uint64_t pct_obj_scanned = n_objects == 0 ? 100 : ((n_obj_scanned * 100) / n_objects);
		uint64_t elapsed         = (cf_getms() - start_time);
		uint64_t est_time        = (elapsed * n_objects)/n_obj_scanned - elapsed;

		cf_info(AS_SINDEX, " Sindex-ticker: ns=%s si=%s obj-scanned=%"PRIu64" si-mem-used=%"PRIu64""
				" progress= %"PRIu64"%% est-time=%"PRIu64" ms",
				ns->name, si_name, n_obj_scanned, si_memory, pct_obj_scanned, est_time);
	}
}

// Sindex ticker end
void
as_sindex_ticker_done(as_namespace * ns, as_sindex * si, uint64_t start_time)
{
	uint64_t si_memory   = 0;
	char   * si_name     = NULL;

	if (si) {
		si_memory        = cf_atomic64_get(si->stats.mem_used);
		si_name          = si->imd->iname;
	}
	else {
		si_memory        = (uint64_t)cf_atomic64_get(ns->sindex_data_memory_used);
		si_name          = "<all>";
	}

	cf_info(AS_SINDEX, "Sindex-ticker done: ns=%s si=%s si-mem-used=%"PRIu64" elapsed=%"PRIu64" ms",
				ns->name, si_name, si_memory, cf_getms() - start_time);

}
//                                       END - SINDEX TICKER
// ************************************************************************************************
// ************************************************************************************************
//                                         INDEX KEYS ARR
// Functions are not used in this file.
static cf_queue *g_q_index_keys_arr = NULL;
int
as_index_keys_ll_reduce_fn(cf_ll_element *ele, void *udata)
{
	return CF_LL_REDUCE_DELETE;
}

void
as_index_keys_ll_destroy_fn(cf_ll_element *ele)
{
	as_index_keys_ll_element * node = (as_index_keys_ll_element *) ele;
	if (node) {
		if (node->keys_arr) {
			as_index_keys_release_arr_to_queue(node->keys_arr);
			node->keys_arr = NULL;
		}
		cf_free(node);
	}
}

as_index_keys_arr *
as_index_get_keys_arr(void)
{
	as_index_keys_arr *keys_arr;
	if (cf_queue_pop(g_q_index_keys_arr, &keys_arr, CF_QUEUE_NOWAIT) == CF_QUEUE_EMPTY) {
		keys_arr = cf_malloc(sizeof(as_index_keys_arr));
	}
	keys_arr->num = 0;
	return keys_arr;
}

void
as_index_keys_release_arr_to_queue(as_index_keys_arr *v)
{
	as_index_keys_arr * keys_arr = (as_index_keys_arr *)v;
	if (cf_queue_sz(g_q_index_keys_arr) < AS_INDEX_KEYS_ARRAY_QUEUE_HIGHWATER) {
		cf_queue_push(g_q_index_keys_arr, &keys_arr);
	}
	else {
		cf_free(keys_arr);
	}

}
//                                      END - INDEX KEYS ARR
// ************************************************************************************************

/*
 * Main initialization function. Talks to Aerospike Index to pull up all the indexes
 * and populates sindex hanging from namespace
 */
int
as_sindex_init(as_namespace *ns)
{
	ns->sindex = cf_malloc(sizeof(as_sindex) * AS_SINDEX_MAX);
	if (!ns->sindex)
		cf_crash(AS_SINDEX,
				"Could not allocation memory for secondary index");

	ns->sindex_cnt = 0;
	for (int i = 0; i < AS_SINDEX_MAX; i++) {
		as_sindex *si                    = &ns->sindex[i];
		memset(si, 0, sizeof(as_sindex));
		si->state                        = AS_SINDEX_INACTIVE;
		si->stats._delete_hist           = NULL;
		si->stats._query_hist            = NULL;
		si->stats._query_batch_lookup    = NULL;
		si->stats._query_batch_io        = NULL;
		si->stats._query_rcnt_hist       = NULL;
		si->stats._query_diff_hist       = NULL;
	}

	// binid to simatch lookup
	if (SHASH_OK != shash_create(&ns->sindex_set_binid_hash,
						as_sindex__set_binid_hash_fn, AS_SINDEX_PROP_KEY_SIZE, sizeof(cf_ll *),
						AS_SINDEX_MAX, 0)) {
		cf_crash(AS_AS, "Couldn't create sindex binid hash");
	}

	// iname to simatch lookup
	if (SHASH_OK != shash_create(&ns->sindex_iname_hash,
						as_sindex__iname_hash_fn, AS_ID_INAME_SZ, sizeof(uint32_t),
						AS_SINDEX_MAX, 0)) {
		cf_crash(AS_AS, "Couldn't create sindex iname hash");
	}

	// Init binid_has_sindex to zero
	memset(ns->binid_has_sindex, 0, sizeof(uint32_t)*AS_BINID_HAS_SINDEX_SIZE);
	if (!g_q_index_keys_arr) {
		g_q_index_keys_arr = cf_queue_create(sizeof(void *), true);
	}
	return AS_SINDEX_OK;
}
