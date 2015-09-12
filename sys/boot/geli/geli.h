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

__FBSDID("$FreeBSD: head/usr.sbin/fstyp/geli.c 285426 2015-07-12 19:16:19Z allanjude $");

#define _STRING_H_	/* Fake this since it comes from util.c */

#include <sys/endian.h>
#include <sys/queue.h>

/* Pull in the sha256 and sha512 implementation */
#include "shacompat.c"

#define CRYPTO_AES_CBC          11
#define CRYPTO_SHA2_512_HMAC    20
#define CRYPTO_AES_XTS          22

#define SHA256_DIGEST_LENGTH    32

#define	G_ELI_VERSION_00	0
#define	G_ELI_VERSION_01	1
#define	G_ELI_VERSION_02	2
#define	G_ELI_VERSION_03	3
#define	G_ELI_VERSION_04	4
#define	G_ELI_VERSION_05	5
#define	G_ELI_VERSION_06	6
#define	G_ELI_VERSION_07	7
#define	G_ELI_VERSION		G_ELI_VERSION_07

/* ON DISK FLAGS. */
/* Use random, onetime keys. */
#define	G_ELI_FLAG_ONETIME		0x00000001
/* Ask for the passphrase from the kernel, before mounting root. */
#define	G_ELI_FLAG_BOOT			0x00000002
/* Detach on last close, if we were open for writing. */
#define	G_ELI_FLAG_WO_DETACH		0x00000004
/* Detach on last close. */
#define	G_ELI_FLAG_RW_DETACH		0x00000008
/* Provide data authentication. */
#define	G_ELI_FLAG_AUTH			0x00000010
/* Provider is read-only, we should deny all write attempts. */
#define	G_ELI_FLAG_RO			0x00000020
/* RUNTIME FLAGS. */
/* Provider was open for writing. */
#define	G_ELI_FLAG_WOPEN		0x00010000
/* Destroy device. */
#define	G_ELI_FLAG_DESTROY		0x00020000
/* Provider uses native byte-order for IV generation. */
#define	G_ELI_FLAG_NATIVE_BYTE_ORDER	0x00040000
/* Provider uses single encryption key. */
#define	G_ELI_FLAG_SINGLE_KEY		0x00080000
/* Device suspended. */
#define	G_ELI_FLAG_SUSPEND		0x00100000
/* Provider uses first encryption key. */
#define	G_ELI_FLAG_FIRST_KEY		0x00200000
/* Provider uses IV-Key for encryption key generation. */
#define	G_ELI_FLAG_ENC_IVKEY		0x00400000

#define	SHA512_MDLEN		64
#define	G_ELI_AUTH_SECKEYLEN	SHA256_DIGEST_LENGTH

#define	G_ELI_MAXMKEYS		2
#define	G_ELI_MAXKEYLEN		64
#define	G_ELI_USERKEYLEN	G_ELI_MAXKEYLEN
#define	G_ELI_DATAKEYLEN	G_ELI_MAXKEYLEN
#define	G_ELI_AUTHKEYLEN	G_ELI_MAXKEYLEN
#define	G_ELI_IVKEYLEN		G_ELI_MAXKEYLEN
#define	G_ELI_SALTLEN		64
#define	G_ELI_DATAIVKEYLEN	(G_ELI_DATAKEYLEN + G_ELI_IVKEYLEN)
/* Data-Key, IV-Key, HMAC_SHA512(Derived-Key, Data-Key+IV-Key) */
#define	G_ELI_MKEYLEN		(G_ELI_DATAIVKEYLEN + SHA512_MDLEN)
/* Switch data encryption key every 2^20 blocks. */
#define	G_ELI_KEY_SHIFT		20

struct g_eli_metadata {
	char		md_magic[16];	/* Magic value. */
	uint32_t	md_version;	/* Version number. */
	uint32_t	md_flags;	/* Additional flags. */
	uint16_t	md_ealgo;	/* Encryption algorithm. */
	uint16_t	md_keylen;	/* Key length. */
	uint16_t	md_aalgo;	/* Authentication algorithm. */
	uint64_t	md_provsize;	/* Provider's size. */
	uint32_t	md_sectorsize;	/* Sector size. */
	uint8_t		md_keys;	/* Available keys. */
	int32_t		md_iterations;	/* Number of iterations for PKCS#5v2. */
	uint8_t		md_salt[G_ELI_SALTLEN]; /* Salt. */
			/* Encrypted master key (IV-key, Data-key, HMAC). */
	uint8_t		md_mkeys[G_ELI_MAXMKEYS * G_ELI_MKEYLEN];
	u_char		md_hash[16];	/* MD5 hash. */
} __packed;

/*
struct fs_ops geli_ufs_fsops = {
	"geli_ufs",
	geli_ufs_open,
	geli_ufs_close,
	geli_ufs_read,
	geli_ufs_write,
	geli_ufs_seek,
	geli_ufs_stat,
	geli_ufs_readdir
};

struct fs_ops geli_zfs_fsops = {
	"geli_zfs",
	geli_zfs_open,
	geli_zfs_close,
	geli_zfs_read,
	geli_zfs_write,
	geli_zfs_seek,
	geli_zfs_stat,
	geli_zfs_readdir
};
*/

static __inline int
eli_metadata_decode(const u_char *data, struct g_eli_metadata *md)
{
	const u_char *p;
	int error = 0;

	bcopy(data, md->md_magic, sizeof(md->md_magic));
	if (strcmp(md->md_magic, "GEOM::ELI") != 0) {
		printf("No magic: ");
		for (int i = 0; i < 16; i++) {
			printf("%c", md->md_magic[i]);
		}
		printf("\n");
	}
	if (strcmp(md->md_magic, "GEOM::ELI") != 0)
		return (1);
	md->md_version = le32dec(data + sizeof(md->md_magic));
	if (md->md_version < 1 && md->md_version > 7)
		return (1);
	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	/* XXXALLAN: Make sure runtime flags are set in here */
	md->md_flags = le32dec(p);	p += sizeof(md->md_flags);
	md->md_ealgo = le16dec(p);	p += sizeof(md->md_ealgo);
	md->md_keylen = le16dec(p);	p += sizeof(md->md_keylen);
	md->md_aalgo = le16dec(p);	p += sizeof(md->md_aalgo);
	md->md_provsize = le64dec(p);	p += sizeof(md->md_provsize);
	md->md_sectorsize = le32dec(p);	p += sizeof(md->md_sectorsize);
	md->md_keys = *p;		p += sizeof(md->md_keys);
	md->md_iterations = le32dec(p);	p += sizeof(md->md_iterations);
	bcopy(p, md->md_salt, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(p, md->md_mkeys, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	/* Don't bother with the MD5 hash in the boot loader */
	bzero(md->md_hash, sizeof(md->md_hash));

	return (error);
}

extern struct fs_ops geli_fsops;

static SLIST_HEAD(geli_list, geli_entry) geli_head = SLIST_HEAD_INITIALIZER(geli_head);
static struct geli_list *geli_headp;
static struct geli_entry {
	struct dsk		*dsk;
	struct g_eli_metadata 	md;
	uint8_t			mkey[G_ELI_DATAIVKEYLEN];
	uint8_t			ekey[G_ELI_DATAKEYLEN];
	uint8_t			ivkey[G_ELI_IVKEYLEN];
	SHA256_CTX		ivctx;
	SLIST_ENTRY(geli_entry)	entries;
} *geli_e, *geli_e_tmp;

static int geli_count;

static void geli_init(void);
static int geli_taste(int read_func(void *vdev, void *priv, off_t off,
    void *buf, size_t bytes), struct dsk *dsk, daddr_t lastsector);
static int is_geli(struct dsk *dsk);
static int geli_read(struct dsk *dsk, off_t offset, u_char *buf, size_t bytes);
static int geli_decrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize, const uint8_t* iv);
static void geli_ivgen(struct geli_entry *geli_e, off_t offset, u_char *iv,
    size_t size);
static void geli_key(struct geli_entry *gep, off_t offset, uint8_t *key);
