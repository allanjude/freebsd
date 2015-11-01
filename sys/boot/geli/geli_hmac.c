/*-
 * Copyright (c) 2015 Allan Jude <allanjude@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

__FBSDID("$FreeBSD: head/usr.sbin/fstyp/geli.c 285426 2015-07-12 19:16:19Z allanjude $");

struct hmac_ctx {
	SHA512_CTX	shactx;
	u_char		k_opad[128];
};

static void geli_hmac_init(struct hmac_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen);
static void geli_hmac_update(struct hmac_ctx *ctx, const uint8_t *data,
    size_t datasize);
static void geli_hmac_final(struct hmac_ctx *ctx, uint8_t *md, size_t mdsize);
static void geli_hmac(const uint8_t *hkey, size_t hkeysize, const uint8_t *data,
    size_t datasize, uint8_t *md, size_t mdsize);
static int geli_mkey_verify(const unsigned char *mkey, const unsigned char *key);
static int geli_mkey_decrypt(struct geli_entry *gep, const unsigned char *key,
    unsigned char *mkey, unsigned *nkeyp);
static void pkcs5v2_genkey(uint8_t *key, unsigned keylen, const uint8_t *salt,
    size_t saltsize, const char *passphrase, u_int iterations);

static void
geli_hmac_init(struct hmac_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen)
{
	u_char k_ipad[128], key[128];
	SHA512_CTX lctx;
	u_int i;

	bzero(key, sizeof(key));
	if (hkeylen == 0)
		; /* do nothing */
	else if (hkeylen <= 128)
		bcopy(hkey, key, hkeylen);
	else {
		/* If key is longer than 128 bytes reset it to key = SHA512(key). */
		SHA512_Init(&lctx);
		SHA512_Update(&lctx, hkey, hkeylen);
		SHA512_Final(key, &lctx);
	}

	/* XOR key with ipad and opad values. */
	for (i = 0; i < sizeof(key); i++) {
		k_ipad[i] = key[i] ^ 0x36;
		ctx->k_opad[i] = key[i] ^ 0x5c;
	}
	bzero(key, sizeof(key));
	/* Perform inner SHA512. */
	SHA512_Init(&ctx->shactx);
	SHA512_Update(&ctx->shactx, k_ipad, sizeof(k_ipad));
	bzero(k_ipad, sizeof(k_ipad));
}

static void
geli_hmac_update(struct hmac_ctx *ctx, const uint8_t *data,
    size_t datasize)
{

	SHA512_Update(&ctx->shactx, data, datasize);
}

static void
geli_hmac_final(struct hmac_ctx *ctx, uint8_t *md, size_t mdsize)
{
	u_char digest[SHA512_MDLEN];
	SHA512_CTX lctx;

	SHA512_Final(digest, &ctx->shactx);
	/* Perform outer SHA512. */
	SHA512_Init(&lctx);
	SHA512_Update(&lctx, ctx->k_opad, sizeof(ctx->k_opad));
	bzero(ctx, sizeof(*ctx));
	SHA512_Update(&lctx, digest, sizeof(digest));
	SHA512_Final(digest, &lctx);
	bzero(&lctx, sizeof(lctx));
	/* mdsize == 0 means "Give me the whole hash!" */
	if (mdsize == 0)
		mdsize = SHA512_MDLEN;
	bcopy(digest, md, mdsize);
	bzero(digest, sizeof(digest));
}

static void
geli_hmac(const uint8_t *hkey, size_t hkeysize, const uint8_t *data,
    size_t datasize, uint8_t *md, size_t mdsize)
{
	struct hmac_ctx ctx;

	geli_hmac_init(&ctx, hkey, hkeysize);
	geli_hmac_update(&ctx, data, datasize);
	geli_hmac_final(&ctx, md, mdsize);
}

/*
 * Verify if the given 'key' is correct.
 * Return 1 if it is correct and 0 otherwise.
 */
static int
geli_mkey_verify(const unsigned char *mkey, const unsigned char *key)
{
	const unsigned char *odhmac;	/* On-disk HMAC. */
	unsigned char chmac[SHA512_MDLEN];	/* Calculated HMAC. */
	unsigned char hmkey[SHA512_MDLEN];	/* Key for HMAC. */

	/*
	 * The key for HMAC calculations is: hmkey = HMAC_SHA512(Derived-Key, 0)
	 */
	geli_hmac(key, G_ELI_USERKEYLEN, "\x00", 1, hmkey, 0);

	odhmac = mkey + G_ELI_DATAIVKEYLEN;

	/* Calculate HMAC from Data-Key and IV-Key. */
	geli_hmac(hmkey, sizeof(hmkey), mkey, G_ELI_DATAIVKEYLEN,
	    chmac, 0);

	bzero(hmkey, sizeof(hmkey));

	/*
	 * Compare calculated HMAC with HMAC from metadata.
	 * If two HMACs are equal, 'key' is correct.
	 */
	return (!bcmp(odhmac, chmac, SHA512_MDLEN));
}

/*
 * Find and decrypt Master Key encrypted with 'key'.
 * Return decrypted Master Key number in 'nkeyp' if not NULL.
 * Return 0 on success, > 0 on failure, -1 on bad key.
 */
static int
geli_mkey_decrypt(struct geli_entry *gep, const unsigned char *key,
    unsigned char *mkey, unsigned *nkeyp)
{
	unsigned char tmpmkey[G_ELI_MKEYLEN];
	unsigned char enckey[SHA512_MDLEN];	/* Key for encryption. */
	unsigned char ivkey[G_ELI_IVKEYLEN];
	const unsigned char *mmkey;
	int bit, error, nkey;

	if (nkeyp != NULL)
		*nkeyp = -1;

	bzero(ivkey, sizeof(ivkey));
	/*
	 * The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	 */
	geli_hmac(key, G_ELI_USERKEYLEN, "\x01", 1, enckey, 0);

	mmkey = gep->md.md_mkeys;
	for (nkey = 0; nkey < G_ELI_MAXMKEYS; nkey++, mmkey += G_ELI_MKEYLEN) {
		bit = (1 << nkey);
		if (!(gep->md.md_keys & bit))
			continue;
		bcopy(mmkey, tmpmkey, G_ELI_MKEYLEN);
		/* gep->md.md_ealgo */
		error = geli_decrypt(CRYPTO_AES_CBC, tmpmkey,
		    G_ELI_MKEYLEN, enckey, gep->md.md_keylen, ivkey);
		if (error != 0) {
			bzero(tmpmkey, sizeof(tmpmkey));
			bzero(enckey, sizeof(enckey));
			return (error);
		}
		if (geli_mkey_verify(tmpmkey, key)) {
			bcopy(tmpmkey, mkey, G_ELI_DATAIVKEYLEN);
			bzero(tmpmkey, sizeof(tmpmkey));
			bzero(enckey, sizeof(enckey));
			if (nkeyp != NULL)
				*nkeyp = nkey;
			return (0);
		}
	}
	bzero(enckey, sizeof(enckey));
	bzero(tmpmkey, sizeof(tmpmkey));
	return (-1);
}

static __inline void
xor(uint8_t *dst, const uint8_t *src, size_t size)
{

	for (; size > 0; size--)
		*dst++ ^= *src++;
}

static void
pkcs5v2_genkey(uint8_t *key, unsigned keylen, const uint8_t *salt,
    size_t saltsize, const char *passphrase, u_int iterations)
{
	uint8_t md[SHA512_MDLEN], saltcount[saltsize + sizeof(uint32_t)];
	uint8_t *counter, *keyp;
	u_int i, bsize, passlen;
	uint32_t count;

	passlen = strlen(passphrase);
	bzero(key, keylen);
	bcopy(salt, saltcount, saltsize);
	counter = saltcount + saltsize;

	keyp = key;
	for (count = 1; keylen > 0; count++, keylen -= bsize, keyp += bsize) {
		bsize = MIN(keylen, sizeof(md));

		counter[0] = (count >> 24) & 0xff;
		counter[1] = (count >> 16) & 0xff;
		counter[2] = (count >> 8) & 0xff;
		counter[3] = count & 0xff;
		geli_hmac(passphrase, passlen, saltcount,
		    sizeof(saltcount), md, 0);
		xor(keyp, md, bsize);

		for(i = 1; i < iterations; i++) {
			geli_hmac(passphrase, passlen, md, sizeof(md),
			    md, 0);
			xor(keyp, md, bsize);
		}
	}
}
