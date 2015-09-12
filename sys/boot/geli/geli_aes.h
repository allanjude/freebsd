/* This code is borrowed from various files in sys/crypto/rijndael */
/*	$FreeBSD$	*/
/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");


/*  Generic Defines  */
#define RIJNDAEL_MAXKC		(256/32)
#define RIJNDAEL_MAXKB		(256/8)
#define RIJNDAEL_MAXNR		14

#define     DIR_ENCRYPT           0 /*  Are we encrpyting?  */
#define     DIR_DECRYPT           1 /*  Are we decrpyting?  */
#define     MODE_ECB              1 /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC              2 /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1             3 /*  Are we ciphering in 1-bit CFB mode? */
#define     BITSPERBLOCK        128 /* Default number of bits in a cipher block */

/*  Error Codes  */
#ifndef TRUE
#define TRUE 1
#endif

#define     BAD_KEY_DIR          -1 /*  Key direction is invalid, e.g., unknown value */
#define     BAD_KEY_MAT          -2 /*  Key material not of correct length */
#define     BAD_KEY_INSTANCE     -3 /*  Key passed is not valid */
#define     BAD_CIPHER_MODE      -4 /*  Params struct passed to cipherInit invalid */
#define     BAD_CIPHER_STATE     -5 /*  Cipher in wrong state (e.g., not initialized) */
#define     BAD_BLOCK_LENGTH     -6
#define     BAD_CIPHER_INSTANCE  -7
#define     BAD_DATA             -8 /*  Data contents are invalid, e.g., invalid padding */
#define     BAD_OTHER            -9 /*  Unknown error */

/*  Algorithm-specific Defines  */
#define     RIJNDAEL_MAX_KEY_SIZE         64 /* # of ASCII char's needed to represent a key */
#define     RIJNDAEL_MAX_IV_SIZE          16 /* # bytes needed to represent an IV  */

/*  Typedefs  */

/*  The structure for key information */
typedef struct {
	int	decrypt;
	int	Nr;		/* key-length-dependent number of rounds */
	uint32_t ek[4 * (RIJNDAEL_MAXNR + 1)];	/* encrypt key schedule */
	uint32_t dk[4 * (RIJNDAEL_MAXNR + 1)];	/* decrypt key schedule */
} rijndael_ctx;

/*  The structure for key information */
typedef struct {
	u_int8_t  direction;            /* Key used for encrypting or decrypting? */
	int   keyLen;                   /* Length of the key  */
	char  keyMaterial[RIJNDAEL_MAX_KEY_SIZE+1];  /* Raw key data in ASCII, e.g., user input or KAT values */
	int   Nr;                       /* key-length-dependent number of rounds */
	u_int32_t   rk[4*(RIJNDAEL_MAXNR + 1)];        /* key schedule */
	u_int32_t   ek[4*(RIJNDAEL_MAXNR + 1)];        /* CFB1 key schedule (encryption only) */
} keyInstance;

typedef u_int8_t		u8;
typedef u_int16_t		u16;
typedef u_int32_t		u32;
typedef u_int8_t		BYTE;

/*  Function prototypes  */

static int	rijndael_makeKey(keyInstance *, u_int8_t, int, const char *);

static int	rijndael_blockDecrypt(keyInstance *, u_int8_t *,
				const u_int8_t *, int, u_int8_t *);

static void	rijndael_set_key(rijndael_ctx *, const u_char *, int);
static void	rijndael_decrypt(const rijndael_ctx *, const u_char *, u_char *);

static int	rijndaelKeySetupEnc(u_int32_t [/*4*(Nr+1)*/], const u_int8_t [], int);
static int	rijndaelKeySetupDec(u_int32_t [/*4*(Nr+1)*/], const u_int8_t [], int);
static void		rijndaelEncrypt(const u_int32_t [/*4*(Nr+1)*/], int,
				const u_int8_t [16], u_int8_t [16]);
static void		rijndaelDecrypt(const u_int32_t [/*4*(Nr+1)*/], int,
				const u_int8_t [16], u_int8_t [16]);
