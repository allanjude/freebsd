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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright (c) 2013, 2018 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/compress.h>
#include <sys/kstat.h>
#include <sys/spa.h>
#include <sys/zfeature.h>
#include <sys/zio.h>
#include <sys/zio_compress.h>

typedef struct zcomp_stats {
	kstat_named_t zcompstat_attempts;
	kstat_named_t zcompstat_empty;
	kstat_named_t zcompstat_skipped_insufficient_gain;
} zcomp_stats_t;

static zcomp_stats_t zcomp_stats = {
	{ "attempts",			KSTAT_DATA_UINT64 },
	{ "empty",			KSTAT_DATA_UINT64 },
	{ "skipped_insufficient_gain",	KSTAT_DATA_UINT64 }
};

#define	ZCOMPSTAT_INCR(stat, val) \
	atomic_add_64(&zcomp_stats.stat.value.ui64, (val));

#define	ZCOMPSTAT_BUMP(stat)		ZCOMPSTAT_INCR(stat, 1);

kstat_t		*zcomp_ksp;

/*
 * If nonzero, every 1/X decompression attempts will fail, simulating
 * an undetected memory error.
 */
uint64_t zio_decompress_fail_fraction = 0;

/*
 * Compression vectors.
 */
zio_compress_info_t zio_compress_table[ZIO_COMPRESS_FUNCTIONS] = {
	{"inherit",	0,	NULL,		NULL,		NULL,	NULL},
	{"on",		0,	NULL,		NULL,		NULL,	NULL},
	{"uncompressed", 0,	NULL,		NULL,		NULL,	NULL},
	{"lzjb",	0,	lzjb_compress,	lzjb_decompress, NULL,	NULL},
	{"empty",	0,	NULL,		NULL, 		NULL,	NULL},
	{"gzip-1",	1,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-2",	2,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-3",	3,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-4",	4,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-5",	5,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-6",	6,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-7",	7,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-8",	8,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"gzip-9",	9,	gzip_compress,	gzip_decompress, NULL,	NULL},
	{"zle",		64,	zle_compress,	zle_decompress,	NULL,	NULL},
	{"lz4",		0,	lz4_compress,	lz4_decompress,	NULL,	NULL},
	{"zstd",	ZIO_ZSTD_LEVEL_DEFAULT,	zstd_compress, zstd_decompress,
	    zstd_decompress_level, zstd_get_level},
};

int32_t
zio_complevel_select(spa_t *spa, int32_t child,
    int32_t parent)
{
	int32_t result;

	ASSERT(child < ZIO_ZSTDLVL_LEVELS);
	ASSERT(parent < ZIO_ZSTDLVL_LEVELS);
	ASSERT(parent != ZIO_ZSTDLVL_INHERIT);

	result = child;
	if (result == ZIO_ZSTDLVL_INHERIT)
		result = parent;

	return (result);
}

enum zio_compress
zio_compress_select(spa_t *spa, enum zio_compress child,
    enum zio_compress parent)
{
	enum zio_compress result;

	ASSERT(child < ZIO_COMPRESS_FUNCTIONS);
	ASSERT(parent < ZIO_COMPRESS_FUNCTIONS);
	ASSERT(parent != ZIO_COMPRESS_INHERIT);

	result = child;
	if (result == ZIO_COMPRESS_INHERIT)
		result = parent;

	if (result == ZIO_COMPRESS_ON) {
		if (spa_feature_is_active(spa, SPA_FEATURE_LZ4_COMPRESS))
			result = ZIO_COMPRESS_LZ4_ON_VALUE;
		else
			result = ZIO_COMPRESS_LEGACY_ON_VALUE;
	}

	return (result);
}

/*ARGSUSED*/
static int
zio_compress_zeroed_cb(void *data, size_t len, void *private)
{
	uint64_t *end = (uint64_t *)((char *)data + len);
	for (uint64_t *word = (uint64_t *)data; word < end; word++)
		if (*word != 0)
			return (1);

	return (0);
}

size_t
zio_compress_data(enum zio_compress c, abd_t *src, void *dst, size_t s_len,
    zio_prop_t *zp)
{
	size_t c_len, d_len;
	int32_t complevel;
	zio_compress_info_t *ci = &zio_compress_table[c];

	ASSERT((uint_t)c < ZIO_COMPRESS_FUNCTIONS);
	ASSERT((uint_t)c == ZIO_COMPRESS_EMPTY || ci->ci_compress != NULL);

	ZCOMPSTAT_BUMP(zcompstat_attempts);

	/*
	 * If the data is all zeroes, we don't even need to allocate
	 * a block for it.  We indicate this by returning zero size.
	 */
	if (abd_iterate_func(src, 0, s_len, zio_compress_zeroed_cb, NULL) == 0) {
		ZCOMPSTAT_BUMP(zcompstat_empty);
		return (0);
	}

	if (c == ZIO_COMPRESS_EMPTY)
		return (s_len);

	/* Compress at least 12.5% */
	d_len = s_len - (s_len >> 3);

	complevel = ci->ci_level;

	if (c == ZIO_COMPRESS_ZSTD) {
		ASSERT(zp != NULL);
		/* If we don't know the level, we can't compress it */
		if (zp->zp_complevel == ZIO_ZSTDLVL_INHERIT)
			return (s_len);

		if (zp->zp_complevel == ZIO_ZSTDLVL_DEFAULT)
			complevel = ZIO_ZSTD_LEVEL_DEFAULT;
		else
			complevel = zp->zp_complevel;

		ASSERT(complevel != ZIO_ZSTDLVL_INHERIT);
	}

	/* No compression algorithms can read from ABDs directly */
	void *tmp = abd_borrow_buf_copy(src, s_len);
	c_len = ci->ci_compress(tmp, dst, s_len, d_len, complevel);
	abd_return_buf(src, tmp, s_len);

	if (c_len > d_len) {
		ZCOMPSTAT_BUMP(zcompstat_skipped_insufficient_gain);
		return (s_len);
	}

	ASSERT3U(c_len, <=, d_len);
	return (c_len);
}

int
zio_decompress_data_buf(enum zio_compress c, void *src, void *dst,
    size_t s_len, size_t d_len, int32_t *level)
{
	zio_compress_info_t *ci = &zio_compress_table[c];
	if ((uint_t)c >= ZIO_COMPRESS_FUNCTIONS || ci->ci_decompress == NULL)
		return (SET_ERROR(EINVAL));

	if (ci->ci_decompress_level != NULL && level != NULL)
		return (ci->ci_decompress_level(src, dst, s_len, d_len, level));

	return (ci->ci_decompress(src, dst, s_len, d_len, ci->ci_level));
}

int
zio_decompress_data(enum zio_compress c, abd_t *src, void *dst,
    size_t s_len, size_t d_len, int32_t *level)
{
	void *tmp = abd_borrow_buf_copy(src, s_len);
	int ret = zio_decompress_data_buf(c, tmp, dst, s_len, d_len, level);
	abd_return_buf(src, tmp, s_len);

	/*
	 * Decompression shouldn't fail, because we've already verifyied
	 * the checksum.  However, for extra protection (e.g. against bitflips
	 * in non-ECC RAM), we handle this error (and test it).
	 */
	ASSERT0(ret);
	if (zio_decompress_fail_fraction != 0 &&
	    spa_get_random(zio_decompress_fail_fraction) == 0)
		ret = SET_ERROR(EINVAL);

	return (ret);
}

int
zio_decompress_getcomplevel(enum zio_compress c, void *src, size_t s_len,
    int32_t *level)
{
	int ret;
	zio_compress_info_t *ci = &zio_compress_table[c];

	if ((uint_t)c >= ZIO_COMPRESS_FUNCTIONS || level == NULL)
		return (SET_ERROR(EINVAL));

	/* Not having this function is non-fatal */
	if (ci->ci_get_level == NULL)
		ret = SET_ERROR(EOPNOTSUPP);
	else
		ret = ci->ci_get_level(src, s_len, level);

	return (ret);
}

int
zio_compress_to_feature(enum zio_compress comp)
{

	switch (comp) {
	case ZIO_COMPRESS_ZSTD:
		return (SPA_FEATURE_ZSTD_COMPRESS);
	}
	return (SPA_FEATURE_NONE);
}

void
zio_compress_init(void)
{

	zcomp_ksp = kstat_create("zfs", 0, "zcompstats", "misc",
	    KSTAT_TYPE_NAMED, sizeof (zcomp_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (zcomp_ksp != NULL) {
		zcomp_ksp->ks_data = &zcomp_stats;
		kstat_install(zcomp_ksp);
	}
}

void
zio_compress_fini(void)
{
	if (zcomp_ksp != NULL) {
		kstat_delete(zcomp_ksp);
		zcomp_ksp = NULL;
	}
}
