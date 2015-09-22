/* This code is borrowed from sys/opencrypto/xform.c */
/*	$OpenBSD: xform.c,v 1.16 2001/08/28 12:20:43 ben Exp $	*/
/*-
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr),
 * Niels Provos (provos@physnet.uni-hamburg.de) and
 * Damien Miller (djm@mindrot.org).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece,
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Additional features in 1999 by Angelos D. Keromytis.
 *
 * AES XTS implementation in 2008 by Damien Miller
 *
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 by John Ioannidis,
 * Angelos D. Keromytis and Niels Provos.
 *
 * Copyright (C) 2001, Angelos D. Keromytis.
 *
 * Copyright (C) 2008, Damien Miller
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by John-Mark Gurney
 * under sponsorship of the FreeBSD Foundation and
 * Rubicon Communications, LLC (Netgate).
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software.
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#define AES_XTS_BLOCKSIZE       16
#define AES_XTS_IVSIZE          8
#define AES_XTS_ALPHA           0x87    /* GF(2^128) generator polynomial */

struct aes_xts_ctx {
	rijndael_ctx key1;
	rijndael_ctx key2;
	u_int8_t tweak[AES_XTS_BLOCKSIZE];
};

static void
aes_xts_reinit(caddr_t key, const u_int8_t *iv)
{
	struct aes_xts_ctx *ctx = (struct aes_xts_ctx *)key;
	u_int64_t blocknum;
	u_int i;

	/*
	 * Prepare tweak as E_k2(IV). IV is specified as LE representation
	 * of a 64-bit block number which we allow to be passed in directly.
	 */
	bcopy(iv, &blocknum, AES_XTS_IVSIZE);
	for (i = 0; i < AES_XTS_IVSIZE; i++) {
		ctx->tweak[i] = blocknum & 0xff;
		blocknum >>= 8;
	}
	/* Last 64 bits of IV are always zero */
	bzero(ctx->tweak + AES_XTS_IVSIZE, AES_XTS_IVSIZE);

	rijndael_encrypt(&ctx->key2, ctx->tweak, ctx->tweak);
}

static void
aes_xts_crypt(struct aes_xts_ctx *ctx, u_int8_t *data, u_int do_encrypt)
{
	u_int8_t block[AES_XTS_BLOCKSIZE];
	u_int i, carry_in, carry_out;

	for (i = 0; i < AES_XTS_BLOCKSIZE; i++)
		block[i] = data[i] ^ ctx->tweak[i];

	if (do_encrypt) {
		printf("Cannot encrypt\n");
		return;
	} else
		rijndael_decrypt(&ctx->key1, block, data);

	for (i = 0; i < AES_XTS_BLOCKSIZE; i++)
		data[i] ^= ctx->tweak[i];

	/* Exponentiate tweak */
	carry_in = 0;
	for (i = 0; i < AES_XTS_BLOCKSIZE; i++) {
		carry_out = ctx->tweak[i] & 0x80;
		ctx->tweak[i] = (ctx->tweak[i] << 1) | (carry_in ? 1 : 0);
		carry_in = carry_out;
	}
	if (carry_in)
		ctx->tweak[0] ^= AES_XTS_ALPHA;
	bzero(block, sizeof(block));
}

static void
aes_xts_encrypt(caddr_t key, u_int8_t *data)
{
	aes_xts_crypt((struct aes_xts_ctx *)key, data, 1);
}

static void
aes_xts_decrypt(caddr_t key, u_int8_t *data)
{
	aes_xts_crypt((struct aes_xts_ctx *)key, data, 0);
}

static void
aes_xts_decrypt_block(caddr_t key, u_int8_t *data, int datasize)
{
	int i;

	for (i = 0; i < datasize; i += AES_XTS_BLOCKSIZE) {
		aes_xts_crypt((struct aes_xts_ctx *)key, data + i, 0);
	}
}

static int
aes_xts_setkey(u_int8_t **sched, const u_int8_t *key, int len)
{
	struct aes_xts_ctx *ctx;

	if (len != 32 && len != 64)
		return (1);

	if (*sched == NULL) {
		*sched = malloc(sizeof(struct aes_xts_ctx));
	}
	if (*sched == NULL)
		return (1);
	ctx = (struct aes_xts_ctx *)*sched;

	rijndael_set_key(&ctx->key1, key, len * 4);
	rijndael_set_key(&ctx->key2, key + (len / 2), len * 4);

	return (0);
}

static void
aes_xts_zerokey(u_int8_t **sched)
{
	bzero(*sched, sizeof(struct aes_xts_ctx));
	/* We do not have free() in the pre-boot environment */
#if 0
	free(*sched);
	*sched = NULL;
#endif
}

