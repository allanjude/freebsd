/*-
 * Copyright (c) 2015 Allan Jude <allanjude@FreeBSD.org>
 * Copyright (c) 2005-2011 Pawel Jakub Dawidek <pawel@dawidek.net>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/usr.sbin/fstyp/geli.c 285426 2015-07-12 19:16:19Z allanjude $");

#include "geli.h"
#include "geli_aes.h"

#include "geli_hmac.c"
#include "geli_aes.c"

#define ENABLE_AESXTS 1
#ifdef ENABLE_AESXTS
#include "geli_opencrypto.c"
#endif

static void
geli_init(void)
{

	geli_count = 0;
	SLIST_INIT(&geli_head);
}

/*
 * Read the last sector of the drive or partition pointed to by dsk and see
 * if it is GELI encrypted
 */
static int
geli_taste(int read_func(void *vdev, void *priv, off_t off, void *buf,
    size_t bytes), struct dsk *dskp, daddr_t lastsector)
{
	struct g_eli_metadata md;
	u_char passphrase[256];
	u_char key[G_ELI_USERKEYLEN], mkey[G_ELI_DATAIVKEYLEN];
	u_char buf[DEV_BSIZE], *mkp;
	u_int keynum;
	struct hmac_ctx ctx;
	int error;

	strcpy(passphrase, "test");
	error = read_func(NULL, dskp, (lastsector) * DEV_BSIZE, &buf, DEV_BSIZE);
	if (error) {
		return (1);
	}
	error = eli_metadata_decode(buf, &md);
	if (error) {
		return (1);
	}

	if (strcmp(md.md_magic, "GEOM::ELI") == 0) {
		if ((md.md_flags & G_ELI_FLAG_ONETIME)) {
			/* Swap device, skip it */
			return (1);
		}
		if ((md.md_flags & G_ELI_FLAG_BOOT)) {
			/* Disk is a GELI boot device */
		}
		geli_e = malloc(sizeof(struct geli_entry));
		geli_e->dsk = dskp;
		geli_e->md = md;

		geli_hmac_init(&ctx, NULL, 0);
		/*
		 * Prepare Derived-Key from the user passphrase.
		 */
		if (geli_e->md.md_iterations == 0) {
			geli_hmac_update(&ctx, geli_e->md.md_salt,
			    sizeof(geli_e->md.md_salt));
			geli_hmac_update(&ctx, passphrase, strlen(passphrase));
			bzero(passphrase, sizeof(passphrase));
		} else if (geli_e->md.md_iterations > 0) {
			u_char dkey[G_ELI_USERKEYLEN];

			pkcs5v2_genkey(dkey, sizeof(dkey), geli_e->md.md_salt,
			    sizeof(geli_e->md.md_salt), passphrase, geli_e->md.md_iterations);
			bzero(passphrase, sizeof(passphrase));
			geli_hmac_update(&ctx, dkey, sizeof(dkey));
			bzero(dkey, sizeof(dkey));
		}

		geli_hmac_final(&ctx, key, 0);

		error = geli_mkey_decrypt(geli_e, key, mkey, &keynum);

		if (error) {
			printf("Failed to decrypt GELI master key: %d\n", error);
			return (1);
		}

		/* Store the keys */
		bcopy(mkey, geli_e->mkey, sizeof(geli_e->mkey));
		bcopy(mkey, geli_e->ivkey, sizeof(geli_e->ivkey));
		mkp = mkey + sizeof(geli_e->ivkey);
		if ((geli_e->md.md_flags & G_ELI_FLAG_AUTH) == 0) {
			bcopy(mkp, geli_e->ekey, G_ELI_DATAKEYLEN);
		} else {
			/*
			 * The encryption key is: ekey = HMAC_SHA512(Data-Key, 0x10)
			 */
			geli_hmac(mkp, G_ELI_MAXKEYLEN, "\x10", 1,
			    geli_e->ekey, 0);
		}

		/* Initialize the per-sector IV */
		SHA256_Init(&geli_e->ivctx);
		SHA256_Update(&geli_e->ivctx, geli_e->ivkey,
		    sizeof(geli_e->ivkey));

		SLIST_INSERT_HEAD(&geli_head, geli_e, entries);
		geli_count++;
		return (0);
	}

	return (1);
}

static int
is_geli(struct dsk *dskp)
{
	SLIST_FOREACH_SAFE(geli_e, &geli_head, entries, geli_e_tmp) {
		if (geli_e->dsk->drive != dskp->drive) {
			continue;
		}
		if (geli_e->dsk->part != dskp->part) {
			/* Right disk, wrong partition */
			continue;
		}
		return (0);
	}
	
	return (1);
}

static int
geli_read(struct dsk *dskp, off_t offset, u_char *buf, size_t bytes)
{
	u_char iv[G_ELI_IVKEYLEN], key[G_ELI_DATAKEYLEN];
	int error;

	SLIST_FOREACH_SAFE(geli_e, &geli_head, entries, geli_e_tmp) {
		if (geli_e->dsk->drive != dskp->drive) {
			continue;
		}
		if (geli_e->dsk->part != dskp->part) {
			/* Right disk, wrong partition */
			continue;
		}

		geli_ivgen(geli_e, offset, iv, G_ELI_IVKEYLEN);

		/* Get the key that corresponds to this offset */
		geli_key(geli_e, offset, key);

		error = geli_decrypt(geli_e->md.md_ealgo, buf,
		    bytes, key, geli_e->md.md_keylen, iv);

		bzero(key, sizeof(key));
		if (error != 0) {
			return (1);
		}
		return (0);
	}

	printf("GELI provider not found\n");
	return (1);
}

static int
geli_decrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize, const uint8_t* iv)
{
	keyInstance aeskey;
#ifdef ENABLE_AESXTS
	struct aes_xts_ctx aesctx;
#endif
	int err, blks;

	switch (algo) {
		case CRYPTO_AES_CBC:
			err = rijndael_makeKey(&aeskey, DIR_DECRYPT, keysize, key);
			if (err) {
				printf("Failed to setup decryption keys\n");
				return (err);
			}
			blks = rijndael_blockDecrypt(&aeskey, iv, data, datasize * 8, data);
			if (datasize != (blks / 8)) {
				printf("Failed to decrypt the entire input\n");
				return (1);
			}
			break;
		case CRYPTO_AES_XTS:
#ifdef ENABLE_AESXTS
			err = aes_xts_setkey(&aesctx, key, keysize / 8);
			if (err) {
				printf("Failed to setup decryption keys\n");
				return (err);
			}
			aes_xts_reinit(&aesctx, iv);
			aes_xts_decrypt_block(&aesctx, data, datasize);
			break;
#endif
		default:
			printf("Unsupported crypto algorithm #%d\n", algo);
			return (1);
	}

	return (0);
}

/*
 * Here we generate IV. It is unique for every sector.
 */
static void
geli_ivgen(struct geli_entry *gep, off_t offset, u_char *iv,
    size_t size)
{
	uint8_t off[8];

	if ((gep->md.md_flags & G_ELI_FLAG_NATIVE_BYTE_ORDER) != 0)
		bcopy(&offset, off, sizeof(off));
	else
		le64enc(off, (uint64_t)offset);

	switch (gep->md.md_ealgo) {
	case CRYPTO_AES_XTS:
		bcopy(off, iv, sizeof(off));
		bzero(iv + sizeof(off), size - sizeof(off));
		break;
	default:
	    {
		u_char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX ctx;

		/* Copy precalculated SHA256 context for IV-Key. */
		bcopy(&gep->ivctx, &ctx, sizeof(ctx));
		SHA256_Update(&ctx, off, sizeof(off));
		SHA256_Final(hash, &ctx);
		bcopy(hash, iv, MIN(sizeof(hash), size));
		break;
	    }
	}
}

static void
geli_key(struct geli_entry *gep, off_t offset, uint8_t *key)
{
	const uint8_t *ekey;
	uint64_t keyno;
	struct {
		char magic[4];
		uint8_t keyno[8];
	} __packed hmacdata;

	if ((gep->md.md_flags & G_ELI_FLAG_ENC_IVKEY) != 0) {
		ekey = gep->mkey;
	} else {
		ekey = gep->ekey;
	}

	keyno = (offset >> G_ELI_KEY_SHIFT) / DEV_BSIZE;
	bcopy("ekey", hmacdata.magic, 4);
	le64enc(hmacdata.keyno, keyno);
	geli_hmac(ekey, G_ELI_MAXKEYLEN, (uint8_t *)&hmacdata,
	    sizeof(hmacdata), key, 0);
}

