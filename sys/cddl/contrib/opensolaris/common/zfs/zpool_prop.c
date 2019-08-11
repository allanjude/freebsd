/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2012, 2017 by Delphix. All rights reserved.
 * Copyright (c) 2014 Integros [integros.com]
 */

#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>

#include "zfs_prop.h"

#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif

static zprop_desc_t zpool_prop_table[ZPOOL_NUM_PROPS];
static zprop_desc_t vdev_prop_table[VDEV_NUM_PROPS];

zprop_desc_t *
zpool_prop_get_table(void)
{
	return (zpool_prop_table);
}

void
zpool_prop_init(void)
{
	static zprop_index_t boolean_table[] = {
		{ "off",	0},
		{ "on",		1},
		{ NULL }
	};

	static zprop_index_t failuremode_table[] = {
		{ "wait",	ZIO_FAILURE_MODE_WAIT },
		{ "continue",	ZIO_FAILURE_MODE_CONTINUE },
		{ "panic",	ZIO_FAILURE_MODE_PANIC },
		{ NULL }
	};

	/* string properties */
	zprop_register_string(ZPOOL_PROP_ALTROOT, "altroot", NULL, PROP_DEFAULT,
	    ZFS_TYPE_POOL, "<path>", "ALTROOT");
	zprop_register_string(ZPOOL_PROP_BOOTFS, "bootfs", NULL, PROP_DEFAULT,
	    ZFS_TYPE_POOL, "<filesystem>", "BOOTFS");
	zprop_register_string(ZPOOL_PROP_CACHEFILE, "cachefile", NULL,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "<file> | none", "CACHEFILE");
	zprop_register_string(ZPOOL_PROP_COMMENT, "comment", NULL,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "<comment-string>", "COMMENT");

	/* readonly number properties */
	zprop_register_number(ZPOOL_PROP_SIZE, "size", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<size>", "SIZE");
	zprop_register_number(ZPOOL_PROP_FREE, "free", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<size>", "FREE");
	zprop_register_number(ZPOOL_PROP_FREEING, "freeing", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<size>", "FREEING");
	zprop_register_number(ZPOOL_PROP_CHECKPOINT, "checkpoint", 0,
	    PROP_READONLY, ZFS_TYPE_POOL, "<size>", "CKPOINT");
	zprop_register_number(ZPOOL_PROP_LEAKED, "leaked", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<size>", "LEAKED");
	zprop_register_number(ZPOOL_PROP_ALLOCATED, "allocated", 0,
	    PROP_READONLY, ZFS_TYPE_POOL, "<size>", "ALLOC");
	zprop_register_number(ZPOOL_PROP_EXPANDSZ, "expandsize", 0,
	    PROP_READONLY, ZFS_TYPE_POOL, "<size>", "EXPANDSZ");
	zprop_register_number(ZPOOL_PROP_FRAGMENTATION, "fragmentation", 0,
	    PROP_READONLY, ZFS_TYPE_POOL, "<percent>", "FRAG");
	zprop_register_number(ZPOOL_PROP_CAPACITY, "capacity", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<size>", "CAP");
	zprop_register_number(ZPOOL_PROP_GUID, "guid", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<guid>", "GUID");
	zprop_register_number(ZPOOL_PROP_HEALTH, "health", 0, PROP_READONLY,
	    ZFS_TYPE_POOL, "<state>", "HEALTH");
	zprop_register_number(ZPOOL_PROP_DEDUPRATIO, "dedupratio", 0,
	    PROP_READONLY, ZFS_TYPE_POOL, "<1.00x or higher if deduped>",
	    "DEDUP");

	/* system partition size */
	zprop_register_number(ZPOOL_PROP_BOOTSIZE, "bootsize", 0, PROP_ONETIME,
	    ZFS_TYPE_POOL, "<size>", "BOOTSIZE");

	/* default number properties */
	zprop_register_number(ZPOOL_PROP_VERSION, "version", SPA_VERSION,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "<version>", "VERSION");
	zprop_register_number(ZPOOL_PROP_DEDUPDITTO, "dedupditto", 0,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "<threshold (min 100)>", "DEDUPDITTO");

	/* default index (boolean) properties */
	zprop_register_index(ZPOOL_PROP_DELEGATION, "delegation", 1,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "on | off", "DELEGATION",
	    boolean_table);
	zprop_register_index(ZPOOL_PROP_AUTOREPLACE, "autoreplace", 0,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "on | off", "REPLACE", boolean_table);
	zprop_register_index(ZPOOL_PROP_LISTSNAPS, "listsnapshots", 0,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "on | off", "LISTSNAPS",
	    boolean_table);
	zprop_register_index(ZPOOL_PROP_AUTOEXPAND, "autoexpand", 0,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "on | off", "EXPAND", boolean_table);
	zprop_register_index(ZPOOL_PROP_READONLY, "readonly", 0,
	    PROP_DEFAULT, ZFS_TYPE_POOL, "on | off", "RDONLY", boolean_table);

	/* default index properties */
	zprop_register_index(ZPOOL_PROP_FAILUREMODE, "failmode",
	    ZIO_FAILURE_MODE_WAIT, PROP_DEFAULT, ZFS_TYPE_POOL,
	    "wait | continue | panic", "FAILMODE", failuremode_table);

	/* hidden properties */
	zprop_register_hidden(ZPOOL_PROP_NAME, "name", PROP_TYPE_STRING,
	    PROP_READONLY, ZFS_TYPE_POOL, "NAME");
	zprop_register_hidden(ZPOOL_PROP_MAXBLOCKSIZE, "maxblocksize",
	    PROP_TYPE_NUMBER, PROP_READONLY, ZFS_TYPE_POOL, "MAXBLOCKSIZE");
	zprop_register_hidden(ZPOOL_PROP_TNAME, "tname", PROP_TYPE_STRING,
	    PROP_ONETIME, ZFS_TYPE_POOL, "TNAME");
	zprop_register_hidden(ZPOOL_PROP_MAXDNODESIZE, "maxdnodesize",
	    PROP_TYPE_NUMBER, PROP_READONLY, ZFS_TYPE_POOL, "MAXDNODESIZE");
}

/*
 * Given a property name and its type, returns the corresponding property ID.
 */
zpool_prop_t
zpool_name_to_prop(const char *propname)
{
	return (zprop_name_to_prop(propname, ZFS_TYPE_POOL));
}

/*
 * Given a pool property ID, returns the corresponding name.
 * Assuming the pool propety ID is valid.
 */
const char *
zpool_prop_to_name(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_name);
}

zprop_type_t
zpool_prop_get_type(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_proptype);
}

boolean_t
zpool_prop_readonly(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_attr == PROP_READONLY);
}

const char *
zpool_prop_default_string(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_strdefault);
}

uint64_t
zpool_prop_default_numeric(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_numdefault);
}

/*
 * Returns true if this is a valid feature@ property.
 */
boolean_t
zpool_prop_feature(const char *name)
{
	static const char *prefix = "feature@";
	return (strncmp(name, prefix, strlen(prefix)) == 0);
}

/*
 * Returns true if this is a valid unsupported@ property.
 */
boolean_t
zpool_prop_unsupported(const char *name)
{
	static const char *prefix = "unsupported@";
	return (strncmp(name, prefix, strlen(prefix)) == 0);
}

int
zpool_prop_string_to_index(zpool_prop_t prop, const char *string,
    uint64_t *index)
{
	return (zprop_string_to_index(prop, string, index, ZFS_TYPE_POOL));
}

int
zpool_prop_index_to_string(zpool_prop_t prop, uint64_t index,
    const char **string)
{
	return (zprop_index_to_string(prop, index, string, ZFS_TYPE_POOL));
}

uint64_t
zpool_prop_random_value(zpool_prop_t prop, uint64_t seed)
{
	return (zprop_random_value(prop, seed, ZFS_TYPE_POOL));
}

#ifndef _KERNEL

const char *
zpool_prop_values(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_values);
}

const char *
zpool_prop_column_name(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_colname);
}

boolean_t
zpool_prop_align_right(zpool_prop_t prop)
{
	return (zpool_prop_table[prop].pd_rightalign);
}
#endif

zprop_desc_t *
vdev_prop_get_table(void)
{
	return (vdev_prop_table);
}

void
vdev_prop_init(void)
{
	static zprop_index_t boolean_table[] = {
		{ "off",	0},
		{ "on",		1},
		{ NULL }
	};

	/* string properties */
	zprop_register_string(VDEV_PROP_COMMENT, "comment", NULL,
	    PROP_DEFAULT, ZFS_TYPE_VDEV, "<comment-string>", "COMMENT");

	/* readonly number properties */
	zprop_register_number(VDEV_PROP_SIZE, "size", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<size>", "SIZE");
	zprop_register_number(VDEV_PROP_FREE, "free", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<size>", "FREE");
	zprop_register_number(VDEV_PROP_ALLOCATED, "allocated", 0,
	    PROP_READONLY, ZFS_TYPE_VDEV, "<size>", "ALLOC");
	zprop_register_number(VDEV_PROP_EXPANDSZ, "expandsize", 0,
	    PROP_READONLY, ZFS_TYPE_VDEV, "<size>", "EXPANDSZ");
	zprop_register_number(VDEV_PROP_FRAGMENTATION, "fragmentation", 0,
	    PROP_READONLY, ZFS_TYPE_VDEV, "<percent>", "FRAG");
	zprop_register_number(VDEV_PROP_CAPACITY, "capacity", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<size>", "CAP");
	zprop_register_number(VDEV_PROP_GUID, "guid", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<guid>", "GUID");
	zprop_register_number(VDEV_PROP_STATE, "STATE", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<state>", "STATE");
	zprop_register_number(VDEV_PROP_BOOTSIZE, "bootsize", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<size>", "BOOTSIZE");
	zprop_register_number(VDEV_PROP_ASIZE, "asize", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<asize>", "ASIZE");
	zprop_register_number(VDEV_PROP_PSIZE, "psize", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<psize>", "PSIZE");
	zprop_register_number(VDEV_PROP_ASHIFT, "ashift", 0, PROP_READONLY,
	    ZFS_TYPE_VDEV, "<ashift>", "ASHIFT");
	zprop_register_number(VDEV_PROP_ROTATION_RATE, "rotation_rate", 0,
	    PROP_READONLY, ZFS_TYPE_VDEV, "<rotation_rate>", "ROTRATE");

	/* default index (boolean) properties */
	zprop_register_index(VDEV_PROP_READONLY, "readonly", 0,
	    PROP_DEFAULT, ZFS_TYPE_VDEV, "on | off", "RDONLY", boolean_table);

	/* default index properties */

	/* hidden properties */
	zprop_register_hidden(VDEV_PROP_NAME, "name", PROP_TYPE_STRING,
	    PROP_READONLY, ZFS_TYPE_VDEV, "NAME");
}

/*
 * Given a property name and its type, returns the corresponding property ID.
 */
vdev_prop_t
vdev_name_to_prop(const char *propname)
{
	char vdevprop[MAXPATHLEN] = { 0 };
	char *vpname = (char *)&vdevprop;
	char *atsign = NULL;

	strlcpy(vpname, propname, sizeof(vdevprop));
	atsign = strchr(vpname, '@');
	if (atsign != NULL)
		*atsign= '\0';

	return (zprop_name_to_prop((const char *)vpname, ZFS_TYPE_VDEV));
}

/*
 * Given a pool property ID, returns the corresponding name.
 * Assuming the pool propety ID is valid.
 */
const char *
vdev_prop_to_name(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_name);
}

zprop_type_t
vdev_prop_get_type(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_proptype);
}

boolean_t
vdev_prop_readonly(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_attr == PROP_READONLY);
}

const char *
vdev_prop_default_string(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_strdefault);
}

uint64_t
vdev_prop_default_numeric(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_numdefault);
}

int
vdev_prop_string_to_index(vdev_prop_t prop, const char *string,
    uint64_t *index)
{
	return (zprop_string_to_index(prop, string, index, ZFS_TYPE_VDEV));
}

int
vdev_prop_index_to_string(vdev_prop_t prop, uint64_t index,
    const char **string)
{
	return (zprop_index_to_string(prop, index, string, ZFS_TYPE_VDEV));
}

/*
 * Returns true if this is a valid vdev property.
 */
boolean_t
zpool_prop_vdev(const char *name)
{
	return (vdev_name_to_prop(name) != VDEV_PROP_INVAL);
}

uint64_t
vdev_prop_random_value(vdev_prop_t prop, uint64_t seed)
{
	return (zprop_random_value(prop, seed, ZFS_TYPE_VDEV));
}

#ifndef _KERNEL
const char *
vdev_prop_values(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_values);
}

const char *
vdev_prop_column_name(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_colname);
}

boolean_t
vdev_prop_align_right(vdev_prop_t prop)
{
	return (vdev_prop_table[prop].pd_rightalign);
}
#endif

