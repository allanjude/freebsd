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
 * Copyright (c) 2016-2018 by Klara Systems Inc.
 * Copyright (c) 2016-2018 Allan Jude <allanjude@freebsd.org>.
 */

#include <netinet/in.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* Allocate just one decompression context and reuse it */
static char *dctxbuf = NULL;
static size_t dctxsize;

static int
zstd_decompress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	const char *src = s_start;
	uint32_t bufsiz = htonl(*(uint32_t *)src);
	uint32_t cookie = htonl(*(uint32_t *)(&src[sizeof (bufsiz)]));
	size_t result;

	ASSERT(d_len >= s_len);

	/* invalid compressed buffer size encoded at start */
	if (bufsiz + sizeof (bufsiz) + sizeof (cookie) > s_len) {
		printf("ZFS: Failed to decode ZSTD decompression header\n");
		return (1);
	}

	/*
	 * Returns 0 on success (decompression function returned non-negative)
	 * and non-zero on failure (decompression function returned negative.
	 */
	ZSTD_DCtx *dctx;

	if (dctxbuf == NULL) {
		dctxsize = ZSTD_estimateDCtxSize();
		dctxbuf = malloc(dctxsize + 8);
		if (dctxbuf == NULL) {
			printf("ZFS: memory allocation failure\n");
			return (1);
		}
		/* Pointer must be 8 byte aligned */
		dctxbuf = (char *)roundup2((uintptr_t)dctxbuf, 8);
	}
	dctx = ZSTD_initStaticDCtx(dctxbuf, dctxsize);
	if (dctx == NULL) {
		printf("ZFS: failed to initialize ZSTD decompress context\n");
		return (1);
	}

	result = ZSTD_decompressDCtx(dctx, d_start, d_len,
	    &src[sizeof (bufsiz) + sizeof (cookie)], bufsiz);
	if (ZSTD_isError(result)) {
		printf("ZFS: Failed to decompress block: %s\n",
		    ZSTD_getErrorName(result));
		return (1);
	}

	return (0);
}
