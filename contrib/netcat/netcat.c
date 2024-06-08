/* $OpenBSD: netcat.c,v 1.226 2023/08/14 08:07:27 tb Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 * Copyright (c) 2015 Bob Beck.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#include <errno.h>
#include <stdio.h>
#include <sys/arb.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/qmath.h>
#include <sys/stats.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <netinet/in.h>
#ifdef IPSEC
#include <netipsec/ipsec.h>
#endif
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/telnet.h>

#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __OpenBSD__
#include <tls.h>
#endif
#include <unistd.h>

#include "atomicio.h"

#define PORT_MAX	65535
#define UNIX_DG_TMP_SOCKET_SIZE	19

#define POLL_STDIN	0
#define POLL_NETOUT	1
#define POLL_NETIN	2
#define POLL_STDOUT	3
#define BUFSIZE		16384

#define TLS_NOVERIFY	(1 << 1)
#define TLS_NONAME	(1 << 2)
#define TLS_CCERT	(1 << 3)
#define TLS_MUSTSTAPLE	(1 << 4)

/* Command Line Options */
int	dflag;					/* detached, no stdin */
int	Fflag;					/* fdpass sock to stdout */
unsigned int iflag;				/* Interval Flag */
int	kflag;					/* More than one connect */
int	lflag;					/* Bind to local port */
int	FreeBSD_stats;				/* Measure using stats(3) */
int	Nflag;					/* shutdown() network socket */
int	nflag;					/* Don't do name look up */
int	FreeBSD_Oflag;				/* Do not use TCP options */
int	FreeBSD_sctp;				/* Use SCTP */
int	FreeBSD_crlf;				/* Convert LF to CRLF */
char   *Pflag;					/* Proxy username */
char   *pflag;					/* Localport flag */
int	rflag;					/* Random ports flag */
char   *sflag;					/* Source Address */
int	tflag;					/* Telnet Emulation */
int	uflag;					/* UDP - Default to TCP */
int	vflag;					/* Verbosity */
int	xflag;					/* Socks proxy */
int	zflag;					/* Port Scan Flag */
int	Dflag;					/* sodebug */
int	Iflag;					/* TCP receive buffer size */
int	Oflag;					/* TCP send buffer size */
int	Sflag;					/* TCP MD5 signature option */
int	Tflag = -1;				/* IP Type of Service */
int	rtableid = -1;

int	usetls;					/* use TLS */
const char    *Cflag;				/* Public cert file */
const char    *Kflag;				/* Private key file */
const char    *oflag;				/* OCSP stapling file */
const char    *Rflag;				/* Root CA file */
int	tls_cachanged;				/* Using non-default CA file */
int	TLSopt;					/* TLS options */
char	*tls_expectname;			/* required name in peer cert */
char	*tls_expecthash;			/* required hash of peer cert */
char	*tls_ciphers;				/* TLS ciphers */
char	*tls_protocols;				/* TLS protocols */
FILE	*Zflag;					/* file to save peer cert */

int recvcount, recvlimit;
int timeout = -1;
int family = AF_UNSPEC;
int tun_fd = -1;
char *portlist[PORT_MAX+1];
char *unix_dg_tmp_socket;
int ttl = -1;
int minttl = -1;

void	atelnet(int, unsigned char *, unsigned int);
int	strtoport(char *portstr, int udp);
void	build_ports(char *);
void	help(void) __attribute__((noreturn));
int	local_listen(const char *, const char *, struct addrinfo);
#ifdef __OpenBSD__
void	readwrite(int, struct tls *);
#else
void	readwrite(int, void *);
#endif
void	fdpass(int nfd) __attribute__((noreturn));
int	remote_connect(const char *, const char *, struct addrinfo, char *);
#ifdef __OpenBSD__
int	timeout_tls(int, struct tls *, int (*)(struct tls *));
#endif
int	timeout_connect(int, const struct sockaddr *, socklen_t);
int	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, int, const char *);
int	udptest(int);
void	connection_info(const char *, const char *, const char *, const char *);
int	unix_bind(char *, int);
int	unix_connect(char *);
int	unix_listen(char *);
void	FreeBSD_stats_setup(int);
void	FreeBSD_stats_print(int);
void	set_common_sockopts(int, int);
int	process_tos_opt(char *, int *);
int	process_tls_opt(char *, int *);
#ifdef __OpenBSD__
void	save_peer_cert(struct tls *_tls_ctx, FILE *_fp);
#endif
void	report_sock(const char *, const struct sockaddr *, socklen_t, char *);
#ifdef __OpenBSD__
void	report_tls(struct tls *tls_ctx, char * host);
#endif
void	usage(int);
#ifdef __OpenBSD__
ssize_t drainbuf(int, unsigned char *, size_t *, struct tls *);
ssize_t fillbuf(int, unsigned char *, size_t *, struct tls *);
void	tls_setup_client(struct tls *, int, char *);
struct tls *tls_setup_server(struct tls *, int, char *);
#else
ssize_t write_wrapper(int, const void *, size_t);
ssize_t drainbuf(int, unsigned char *, size_t *, void *, int);
ssize_t fillbuf(int, unsigned char *, size_t *, void *);
#endif

#ifdef IPSEC
void	add_ipsec_policy(int, int, char *);

char	*ipsec_policy[2];
#endif

enum {
	FREEBSD_TUN = CHAR_MAX,	/* avoid collision with return values from getopt */
};

int
main(int argc, char *argv[])
{
	int ch, s = -1, ret, socksv;
	char *host, *uport;
	int numfibs, ipsec_count = 0;
	size_t intsize = sizeof(int);
	char ipaddr[NI_MAXHOST];
	struct addrinfo hints;
	socklen_t len;
	struct sockaddr_storage cliaddr;
	char *proxy = NULL, *proxyport = NULL;
	const char *errstr, *tundev = NULL;
	struct addrinfo proxyhints;
	char unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];
#ifdef __OpenBSD__
	struct tls_config *tls_cfg = NULL;
	struct tls *tls_ctx = NULL;
	uint32_t protocols;
#endif
	struct option longopts[] = {
		{ "crlf",	no_argument,	&FreeBSD_crlf,	1 },
		{ "help",	no_argument,	NULL,		'h' },
		{ "no-tcpopt",	no_argument,	&FreeBSD_Oflag,	1 },
		{ "sctp",	no_argument,	&FreeBSD_sctp,	1 },
		{ "stats",	no_argument,	&FreeBSD_stats,	1 },
		{ "tun",	required_argument,	NULL,	FREEBSD_TUN },
		{ NULL,		0,		NULL,		0 }
	};

	ret = 1;
	socksv = 5;
	host = NULL;
	uport = NULL;
#ifdef __OpenBSD__
	Rflag = tls_default_ca_cert_file();
#endif

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv,
	    "46DdEe:FhI:i:klM:m:NnO:P:p:rSs:T:tUuV:vW:w:X:x:z",
	    longopts, NULL)) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'U':
			family = AF_UNIX;
			break;
		case 'X':
			if (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			else if (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			else if (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			else
				errx(1, "unsupported proxy protocol");
			break;
#ifdef __OpenBSD__
		case 'C':
			Cflag = optarg;
			break;
		case 'c':
			usetls = 1;
			break;
#endif
		case 'd':
			dflag = 1;
			break;
		case 'e':
#ifdef __OpenBSD__
			tls_expectname = optarg;
#else /* __OpenBSD__ */
#ifdef IPSEC
			ipsec_policy[ipsec_count++ % 2] = optarg;
#else /* IPSEC */
			errx(1, "IPsec support unavailable.");
#endif /* IPSEC */
#endif /* __OpenBSD__ */
			break;
		case 'E':
#ifdef IPSEC
			ipsec_policy[0] = "in  ipsec esp/transport//require";
			ipsec_policy[1] = "out ipsec esp/transport//require";
#else
			errx(1, "IPsec support unavailable.");
#endif
			break;
		case 'F':
			Fflag = 1;
			break;
#ifdef __OpenBSD__
		case 'H':
			tls_expecthash = optarg;
			break;
#endif
		case 'h':
			help();
			break;
		case 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			if (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			break;
#ifdef __OpenBSD__
		case 'K':
			Kflag = optarg;
			break;
#endif
		case 'k':
			kflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'M':
			ttl = strtonum(optarg, 0, 255, &errstr);
			if (errstr)
				errx(1, "ttl is %s", errstr);
			break;
		case 'm':
			minttl = strtonum(optarg, 0, 255, &errstr);
			if (errstr)
				errx(1, "minttl is %s", errstr);
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'P':
			Pflag = optarg;
			break;
		case 'p':
			pflag = optarg;
			break;
#ifdef __OpenBSD__
		case 'R':
			tls_cachanged = 1;
			Rflag = optarg;
			break;
#endif
		case 'r':
			rflag = 1;
			break;
		case 's':
			sflag = optarg;
			break;
		case 't':
			tflag = 1;
			break;
		case 'u':
			uflag = 1;
			break;
		case 'V':
			if (sysctlbyname("net.fibs", &numfibs, &intsize, NULL, 0) == -1)
				errx(1, "Multiple FIBS not supported");
			rtableid = (int)strtonum(optarg, 0,
			    numfibs - 1, &errstr);
			if (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			break;
		case 'v':
			vflag = 1;
			break;
		case 'W':
			recvlimit = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr)
				errx(1, "receive limit %s: %s", errstr, optarg);
			break;
		case 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			if (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			break;
		case 'x':
			xflag = 1;
			if ((proxy = strdup(optarg)) == NULL)
				err(1, NULL);
			break;
		case 'Z':
			if (strcmp(optarg, "-") == 0)
				Zflag = stderr;
			else if ((Zflag = fopen(optarg, "w")) == NULL)
				err(1, "can't open %s", optarg);
			break;
		case 'z':
			zflag = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		case 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			if (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			break;
		case 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			if (errstr != NULL) {
			    if (strcmp(errstr, "invalid") != 0)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			}
			break;
#ifdef __OpenBSD__
		case 'o':
			oflag = optarg;
			break;
#endif
		case 'S':
			Sflag = 1;
			break;
		case 'T':
			errstr = NULL;
			errno = 0;
#ifdef __OpenBSD__
			if (process_tls_opt(optarg, &TLSopt))
				break;
#endif
			if (process_tos_opt(optarg, &Tflag))
				break;
			if (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (int)strtol(optarg, NULL, 16);
			else
				Tflag = (int)strtonum(optarg, 0, 255,
				    &errstr);
			if (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos/tls value %s", optarg);
			break;
		case FREEBSD_TUN:
			tundev = optarg;
			break;
		case 0:
			/* Long option. */
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

#ifdef __OpenBSD__
	if (rtableid >= 0)
		if (setrtable(rtableid) == -1)
			err(1, "setrtable");
#endif

	/* Cruft to make sure options are clean, and used properly. */
	if (argc == 1 && family == AF_UNIX) {
		host = argv[0];
	} else if (argc == 1 && lflag) {
		uport = argv[0];
	} else if (argc == 2) {
		host = argv[0];
		uport = argv[1];
	} else
		usage(1);

#ifdef __OpenBSD__
	if (usetls) {
		if (Cflag && unveil(Cflag, "r") == -1)
			err(1, "unveil %s", Cflag);
		if (unveil(Rflag, "r") == -1)
			err(1, "unveil %s", Rflag);
		if (Kflag && unveil(Kflag, "r") == -1)
			err(1, "unveil %s", Kflag);
		if (oflag && unveil(oflag, "r") == -1)
			err(1, "unveil %s", oflag);
	} else if (family == AF_UNIX && uflag && lflag && !kflag) {
		/*
		 * After recvfrom(2) from client, the server connects
		 * to the client socket.  As the client path is determined
		 * during runtime, we cannot unveil(2).
		 */
	} else {
		if (family == AF_UNIX) {
			if (unveil(host, "rwc") == -1)
				err(1, "unveil %s", host);
			if (uflag && !kflag) {
				if (sflag) {
					if (unveil(sflag, "rwc") == -1)
						err(1, "unveil %s", sflag);
				} else {
					if (unveil("/tmp", "rwc") == -1)
						err(1, "unveil /tmp");
				}
			}
		} else {
			/* no filesystem visibility */
			if (unveil("/", "") == -1)
				err(1, "unveil /");
		}
	}

	if (family == AF_UNIX) {
		if (pledge("stdio rpath wpath cpath tmppath unix", NULL) == -1)
			err(1, "pledge");
	} else if (Fflag && Pflag) {
		if (pledge("stdio inet dns sendfd tty", NULL) == -1)
			err(1, "pledge");
	} else if (Fflag) {
		if (pledge("stdio inet dns sendfd", NULL) == -1)
			err(1, "pledge");
	} else if (Pflag && usetls) {
		if (pledge("stdio rpath inet dns tty", NULL) == -1)
			err(1, "pledge");
	} else if (Pflag) {
		if (pledge("stdio inet dns tty", NULL) == -1)
			err(1, "pledge");
	} else if (usetls) {
		if (pledge("stdio rpath inet dns", NULL) == -1)
			err(1, "pledge");
	} else if (pledge("stdio inet dns", NULL) == -1)
		err(1, "pledge");
#endif

	if (lflag && sflag)
		errx(1, "cannot use -s and -l");
	if (lflag && pflag)
		errx(1, "cannot use -p and -l");
	if (lflag && zflag)
		errx(1, "cannot use -z and -l");
	if (!lflag && kflag)
		errx(1, "must use -l with -k");
	if (FreeBSD_sctp) {
		if (uflag)
			errx(1, "cannot use -u and --sctp");
		if (family == AF_UNIX)
			errx(1, "cannot use -U and --sctp");
	}
	if (tundev != NULL) {
		if (!uflag)
			errx(1, "must use --tun with -u");
		tun_fd = open(tundev, O_RDWR);
		if (tun_fd == -1)
			errx(1, "unable to open tun device %s", tundev);
	}
	if (uflag && usetls)
		errx(1, "cannot use -c and -u");
	if ((family == AF_UNIX) && usetls)
		errx(1, "cannot use -c and -U");
	if ((family == AF_UNIX) && Fflag)
		errx(1, "cannot use -F and -U");
	if (Fflag && usetls)
		errx(1, "cannot use -c and -F");
	if (TLSopt && !usetls)
		errx(1, "you must specify -c to use TLS options");
	if (Cflag && !usetls)
		errx(1, "you must specify -c to use -C");
	if (Kflag && !usetls)
		errx(1, "you must specify -c to use -K");
	if (Zflag && !usetls)
		errx(1, "you must specify -c to use -Z");
	if (oflag && !Cflag)
		errx(1, "you must specify -C to use -o");
	if (tls_cachanged && !usetls)
		errx(1, "you must specify -c to use -R");
	if (tls_expecthash && !usetls)
		errx(1, "you must specify -c to use -H");
	if (tls_expectname && !usetls)
		errx(1, "you must specify -c to use -e");

	/* Get name of temporary socket for unix datagram client */
	if ((family == AF_UNIX) && uflag && !lflag) {
		if (sflag) {
			unix_dg_tmp_socket = sflag;
		} else {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
			    UNIX_DG_TMP_SOCKET_SIZE);
			if (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	if (family != AF_UNIX) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP :
		    FreeBSD_sctp ? IPPROTO_SCTP : IPPROTO_TCP;
		if (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	if (xflag) {
		if (uflag)
			errx(1, "no proxy support for UDP mode");

		if (FreeBSD_sctp)
			errx(1, "no proxy support for SCTP mode");

		if (lflag)
			errx(1, "no proxy support for listen");

		if (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		if (sflag)
			errx(1, "no proxy support for local source address");

		if (*proxy == '[') {
			++proxy;
			proxyport = strchr(proxy, ']');
			if (proxyport == NULL)
				errx(1, "missing closing bracket in proxy");
			*proxyport++ = '\0';
			if (*proxyport == '\0')
				/* Use default proxy port. */
				proxyport = NULL;
			else {
				if (*proxyport == ':')
					++proxyport;
				else
					errx(1, "garbage proxy port delimiter");
			}
		} else {
			proxyport = strrchr(proxy, ':');
			if (proxyport != NULL)
				*proxyport++ = '\0';
		}

		memset(&proxyhints, 0, sizeof(struct addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		if (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

#ifdef __OpenBSD__
	if (usetls) {
		if ((tls_cfg = tls_config_new()) == NULL)
			errx(1, "unable to allocate TLS config");
		if (Rflag && tls_config_set_ca_file(tls_cfg, Rflag) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (Cflag && tls_config_set_cert_file(tls_cfg, Cflag) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (Kflag && tls_config_set_key_file(tls_cfg, Kflag) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (oflag && tls_config_set_ocsp_staple_file(tls_cfg, oflag) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (tls_config_parse_protocols(&protocols, tls_protocols) == -1)
			errx(1, "invalid TLS protocols `%s'", tls_protocols);
		if (tls_config_set_protocols(tls_cfg, protocols) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (tls_config_set_ciphers(tls_cfg, tls_ciphers) == -1)
			errx(1, "%s", tls_config_error(tls_cfg));
		if (!lflag && (TLSopt & TLS_CCERT))
			errx(1, "clientcert is only valid with -l");
		if (TLSopt & TLS_NONAME)
			tls_config_insecure_noverifyname(tls_cfg);
		if (TLSopt & TLS_NOVERIFY) {
			if (tls_expecthash != NULL)
				errx(1, "-H and -T noverify may not be used "
				    "together");
			tls_config_insecure_noverifycert(tls_cfg);
		}
		if (TLSopt & TLS_MUSTSTAPLE)
			tls_config_ocsp_require_stapling(tls_cfg);

		if (Pflag) {
			if (pledge("stdio inet dns tty", NULL) == -1)
				err(1, "pledge");
		} else if (pledge("stdio inet dns", NULL) == -1)
			err(1, "pledge");
	}
#endif
	if (lflag) {
		ret = 0;

		if (family == AF_UNIX) {
			if (uflag)
				s = unix_bind(host, 0);
			else
				s = unix_listen(host);
		}

#ifdef __OpenBSD__
		if (usetls) {
			tls_config_verify_client_optional(tls_cfg);
			if ((tls_ctx = tls_server()) == NULL)
				errx(1, "tls server creation failed");
			if (tls_configure(tls_ctx, tls_cfg) == -1)
				errx(1, "tls configuration failed (%s)",
				    tls_error(tls_ctx));
		}
#endif
		/* Allow only one connection at a time, but stay alive. */
		for (;;) {
			if (family != AF_UNIX) {
				if (s != -1)
					close(s);
				s = local_listen(host, uport, hints);
			}
			if (s == -1)
				err(1, NULL);
			if (uflag && kflag) {
#ifdef __OpenBSD__
				if (family == AF_UNIX) {
					if (pledge("stdio unix", NULL) == -1)
						err(1, "pledge");
				}
#endif
				/*
				 * For UDP and -k, don't connect the socket,
				 * let it receive datagrams from multiple
				 * socket pairs.
				 */
				readwrite(s, NULL);
			} else if (uflag && !kflag) {
				/*
				 * For UDP and not -k, we will use recvfrom()
				 * initially to wait for a caller, then use
				 * the regular functions to talk to the caller.
				 */
				int rv;
				char buf[2048];
				struct sockaddr_storage z;

				len = sizeof(z);
				rv = recvfrom(s, buf, sizeof(buf), MSG_PEEK,
				    (struct sockaddr *)&z, &len);
				if (rv == -1)
					err(1, "recvfrom");

				rv = connect(s, (struct sockaddr *)&z, len);
				if (rv == -1)
					err(1, "connect");

#ifdef __OpenBSD__
				if (family == AF_UNIX) {
					if (pledge("stdio unix", NULL) == -1)
						err(1, "pledge");
				}
#endif
				if (vflag)
					report_sock("Connection received",
					    (struct sockaddr *)&z, len,
					    family == AF_UNIX ? host : NULL);

				readwrite(s, NULL);
			} else {
#ifdef __OpenBSD__
				struct tls *tls_cctx = NULL;
#endif
				int connfd;

				len = sizeof(cliaddr);
				connfd = accept4(s, (struct sockaddr *)&cliaddr,
				    &len, SOCK_NONBLOCK);
				if (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				if (vflag)
					report_sock("Connection received",
					    (struct sockaddr *)&cliaddr, len,
					    family == AF_UNIX ? host : NULL);
#ifdef __OpenBSD__
				if ((usetls) &&
				    (tls_cctx = tls_setup_server(tls_ctx, connfd, host)))
					readwrite(connfd, tls_cctx);
				if (!usetls)
					readwrite(connfd, NULL);
				if (tls_cctx)
					timeout_tls(s, tls_cctx, tls_close);
#else
				if (FreeBSD_stats)
					FreeBSD_stats_setup(connfd);
				readwrite(connfd, NULL);
#endif
				close(connfd);
#ifdef __OpenBSD__
				tls_free(tls_cctx);
#endif
			}
			if (family == AF_UNIX && uflag) {
				if (connect(s, NULL, 0) == -1)
					err(1, "connect");
			}

			if (!kflag)
				break;
		}
	} else if (family == AF_UNIX) {
		ret = 0;

		if ((s = unix_connect(host)) > 0) {
			if (!zflag)
				readwrite(s, NULL);
			close(s);
		} else {
			warn("%s", host);
			ret = 1;
		}

		if (uflag)
			unlink(unix_dg_tmp_socket);
		return ret;
	} else {
		int i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		for (s = -1, i = 0; portlist[i] != NULL; i++) {
			if (s != -1)
				close(s);
#ifdef __OpenBSD__
			tls_free(tls_ctx);
			tls_ctx = NULL;

			if (usetls) {
				if ((tls_ctx = tls_client()) == NULL)
					errx(1, "tls client creation failed");
				if (tls_configure(tls_ctx, tls_cfg) == -1)
					errx(1, "tls configuration failed (%s)",
					    tls_error(tls_ctx));
			}
#endif
			if (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxy, proxyport, proxyhints, socksv,
				    Pflag);
			else
				s = remote_connect(host, portlist[i], hints,
				    ipaddr);

			if (s == -1)
				continue;

			ret = 0;
			if (vflag || zflag) {
				int print_info = 1;

				/* For UDP, make sure we are connected. */
				if (uflag) {
					/* No info on failed or skipped test. */
					if ((print_info = udptest(s)) == -1) {
						ret = 1;
						continue;
					}
				}
				if (print_info == 1)
					connection_info(host, portlist[i],
					    uflag ? "udp" : "tcp", ipaddr);
			}
			if (Fflag)
				fdpass(s);
			else {
#ifdef __OpenBSD__
				if (usetls)
					tls_setup_client(tls_ctx, s, host);
				if (!zflag)
					readwrite(s, tls_ctx);
				if (tls_ctx)
					timeout_tls(s, tls_ctx, tls_close);
#else
				if (!zflag)
					readwrite(s, NULL);
#endif
			}
		}
	}

	if (s != -1)
		close(s);
	if (tun_fd != -1)
		close(tun_fd);
#ifdef __OpenBSD__
	tls_free(tls_ctx);
	tls_config_free(tls_cfg);
#endif

	return ret;
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
int
unix_bind(char *path, int flags)
{
	struct sockaddr_un s_un;
	int s, save_errno;

	/* Create unix domain socket. */
	if ((s = socket(AF_UNIX, flags | (uflag ? SOCK_DGRAM : SOCK_STREAM),
	    0)) == -1)
		return -1;

	memset(&s_un, 0, sizeof(struct sockaddr_un));
	s_un.sun_family = AF_UNIX;

	if (strlcpy(s_un.sun_path, path, sizeof(s_un.sun_path)) >=
	    sizeof(s_un.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		return -1;
	}

	if (bind(s, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		save_errno = errno;
		close(s);
		errno = save_errno;
		return -1;
	}
	if (vflag)
		report_sock("Bound", NULL, 0, path);

	return s;
}

#ifdef __OpenBSD__
int
timeout_tls(int s, struct tls *tls_ctx, int (*func)(struct tls *))
{
	struct pollfd pfd;
	int ret;

	while ((ret = (*func)(tls_ctx)) != 0) {
		if (ret == TLS_WANT_POLLIN)
			pfd.events = POLLIN;
		else if (ret == TLS_WANT_POLLOUT)
			pfd.events = POLLOUT;
		else
			break;
		pfd.fd = s;
		if ((ret = poll(&pfd, 1, timeout)) == 1)
			continue;
		else if (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
			break;
		} else
			err(1, "poll failed");
	}

	return ret;
}

void
tls_setup_client(struct tls *tls_ctx, int s, char *host)
{
	const char *errstr;

	if (tls_connect_socket(tls_ctx, s,
	    tls_expectname ? tls_expectname : host) == -1) {
		errx(1, "tls connection failed (%s)",
		    tls_error(tls_ctx));
	}
	if (timeout_tls(s, tls_ctx, tls_handshake) == -1) {
		if ((errstr = tls_error(tls_ctx)) == NULL)
			errstr = strerror(errno);
		errx(1, "tls handshake failed (%s)", errstr);
	}
	if (vflag)
		report_tls(tls_ctx, host);
	if (tls_expecthash && (tls_peer_cert_hash(tls_ctx) == NULL ||
	    strcmp(tls_expecthash, tls_peer_cert_hash(tls_ctx)) != 0))
		errx(1, "peer certificate is not %s", tls_expecthash);
	if (Zflag) {
		save_peer_cert(tls_ctx, Zflag);
		if (Zflag != stderr && (fclose(Zflag) != 0))
			err(1, "fclose failed saving peer cert");
	}
}

struct tls *
tls_setup_server(struct tls *tls_ctx, int connfd, char *host)
{
	struct tls *tls_cctx;
	const char *errstr;

	if (tls_accept_socket(tls_ctx, &tls_cctx, connfd) == -1) {
		warnx("tls accept failed (%s)", tls_error(tls_ctx));
	} else if (timeout_tls(connfd, tls_cctx, tls_handshake) == -1) {
		if ((errstr = tls_error(tls_cctx)) == NULL)
			errstr = strerror(errno);
		warnx("tls handshake failed (%s)", errstr);
	} else {
		int gotcert = tls_peer_cert_provided(tls_cctx);

		if (vflag && gotcert)
			report_tls(tls_cctx, host);
		if ((TLSopt & TLS_CCERT) && !gotcert)
			warnx("No client certificate provided");
		else if (gotcert && tls_expecthash &&
		    (tls_peer_cert_hash(tls_cctx) == NULL ||
		    strcmp(tls_expecthash, tls_peer_cert_hash(tls_cctx)) != 0))
			warnx("peer certificate is not %s", tls_expecthash);
		else if (gotcert && tls_expectname &&
		    (!tls_peer_cert_contains_name(tls_cctx, tls_expectname)))
			warnx("name (%s) not found in client cert",
			    tls_expectname);
		else {
			return tls_cctx;
		}
	}
	return NULL;
}
#endif

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
int
unix_connect(char *path)
{
	struct sockaddr_un s_un;
	int s, save_errno;

	if (uflag) {
		if ((s = unix_bind(unix_dg_tmp_socket, SOCK_CLOEXEC)) == -1)
			return -1;
	} else {
		if ((s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
			return -1;
	}

	memset(&s_un, 0, sizeof(struct sockaddr_un));
	s_un.sun_family = AF_UNIX;

	if (strlcpy(s_un.sun_path, path, sizeof(s_un.sun_path)) >=
	    sizeof(s_un.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		return -1;
	}
	if (connect(s, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		save_errno = errno;
		close(s);
		errno = save_errno;
		return -1;
	}
	return s;
}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
int
unix_listen(char *path)
{
	int s;

	if ((s = unix_bind(path, 0)) == -1)
		return -1;
	if (listen(s, 5) == -1) {
		close(s);
		return -1;
	}
	if (vflag)
		report_sock("Listening", NULL, 0, path);

	return s;
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
int
remote_connect(const char *host, const char *port, struct addrinfo hints,
    char *ipaddr)
{
	struct addrinfo *res, *res0;
	int s = -1, error, herr, on = 1, save_errno;

	if ((error = getaddrinfo(host, port, &hints, &res0)))
		errx(1, "getaddrinfo for host \"%s\" port %s: %s", host,
		    port, gai_strerror(error));

	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype |
		    SOCK_NONBLOCK, res->ai_protocol)) == -1)
			continue;

		if (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_SETFIB,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_SETFIB");

		/* Bind to a local port or source address if specified. */
		if (sflag || pflag) {
			struct addrinfo ahints, *ares;

			/* try IP_BINDANY, but don't insist */
			setsockopt(s, IPPROTO_IP, IP_BINDANY, &on, sizeof(on));
			memset(&ahints, 0, sizeof(struct addrinfo));
			ahints.ai_family = res->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			if ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			if (bind(s, (struct sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) == -1)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res->ai_family);

		if (ipaddr != NULL) {
			herr = getnameinfo(res->ai_addr, res->ai_addrlen,
			    ipaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			switch (herr) {
			case 0:
				break;
			case EAI_SYSTEM:
				err(1, "getnameinfo");
			default:
				errx(1, "getnameinfo: %s", gai_strerror(herr));
			}
		}

		if (timeout_connect(s, res->ai_addr, res->ai_addrlen) == 0)
			break;

		if (vflag) {
			/* only print IP if there is something to report */
			if (nflag || ipaddr == NULL ||
			    (strncmp(host, ipaddr, NI_MAXHOST) == 0))
				warn("connect to %s port %s (%s) failed", host,
				    port, uflag ? "udp" : "tcp");
			else
				warn("connect to %s (%s) port %s (%s) failed",
				    host, ipaddr, port, uflag ? "udp" : "tcp");
		}

		save_errno = errno;
		close(s);
		errno = save_errno;
		s = -1;
	}

	freeaddrinfo(res0);

	return s;
}

int
timeout_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct pollfd pfd;
	socklen_t optlen;
	int optval;
	int ret;

	if ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		if ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = sizeof(optval);
			if ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} else if (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} else
			err(1, "poll failed");
	}

	return ret;
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
int
local_listen(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	int s = -1, ret, x = 1, save_errno;
	int error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	if (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	if ((error = getaddrinfo(host, port, &hints, &res0)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol)) == -1)
			continue;

		if (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_SETFIB,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_SETFIB");

		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
		if (ret == -1)
			err(1, NULL);

		if (FreeBSD_Oflag) {
			if (setsockopt(s, IPPROTO_TCP, TCP_NOOPT,
			    &FreeBSD_Oflag, sizeof(FreeBSD_Oflag)) == -1)
				err(1, "disable TCP options");
		}

		set_common_sockopts(s, res->ai_family);

		if (bind(s, (struct sockaddr *)res->ai_addr,
		    res->ai_addrlen) == 0)
			break;

		save_errno = errno;
		close(s);
		errno = save_errno;
		s = -1;
	}

	if (!uflag && s != -1) {
		if (listen(s, 1) == -1)
			err(1, "listen");
	}
	if (vflag && s != -1) {
		struct sockaddr_storage ss;
		socklen_t len;

		len = sizeof(ss);
		if (getsockname(s, (struct sockaddr *)&ss, &len) == -1)
			err(1, "getsockname");
		report_sock(uflag ? "Bound" : "Listening",
		    (struct sockaddr *)&ss, len, NULL);
	}

	freeaddrinfo(res0);

	return s;
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
#ifdef __OpenBSD__
readwrite(int net_fd, struct tls *tls_ctx)
#else
readwrite(int net_fd, void *tls_ctx)
#endif
{
	struct pollfd pfd[4];
	int stdin_fd = STDIN_FILENO;
	int stdout_fd = STDOUT_FILENO;
	unsigned char netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned char stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	int n, num_fds;
	int stats_printed = 0;
	ssize_t ret;

	/* don't read from stdin if requested */
	if (dflag)
		stdin_fd = -1;

	/* stdin */
	pfd[POLL_STDIN].fd = (tun_fd != -1) ? tun_fd : stdin_fd;
	pfd[POLL_STDIN].events = POLLIN;

	/* network out */
	pfd[POLL_NETOUT].fd = net_fd;
	pfd[POLL_NETOUT].events = 0;

	/* network in */
	pfd[POLL_NETIN].fd = net_fd;
	pfd[POLL_NETIN].events = POLLIN;

	/* stdout */
	pfd[POLL_STDOUT].fd = (tun_fd != -1) ? tun_fd : stdout_fd;
	pfd[POLL_STDOUT].events = 0;

	while (1) {
		/* both inputs are gone, buffers are empty, we are done */
		if (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1 &&
		    stdinbufpos == 0 && netinbufpos == 0) {
			if (FreeBSD_stats && !stats_printed)
				FreeBSD_stats_print(net_fd);
			return;
		}
		/* both outputs are gone, we can't continue */
		if (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			if (FreeBSD_stats && !stats_printed)
				FreeBSD_stats_print(net_fd);
			return;
		}
		/* listen and net in gone, queues empty, done */
		if (lflag && pfd[POLL_NETIN].fd == -1 &&
		    stdinbufpos == 0 && netinbufpos == 0) {
			if (FreeBSD_stats && !stats_printed)
				FreeBSD_stats_print(net_fd);
			return;
		}
		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		if (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		if (num_fds == -1)
			err(1, "polling error");

		/* timeout happened */
		if (num_fds == 0) {
			if (FreeBSD_stats)
				FreeBSD_stats_print(net_fd);
			return;
		}

		/* treat socket error conditions */
		for (n = 0; n < 4; n++) {
			if (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		if (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    !(pfd[POLL_STDIN].revents & POLLIN))
			pfd[POLL_STDIN].fd = -1;

		if (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    !(pfd[POLL_NETIN].revents & POLLIN))
			pfd[POLL_NETIN].fd = -1;

		if (pfd[POLL_NETOUT].revents & POLLHUP) {
			if (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		if (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		if (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		if (pfd[POLL_STDOUT].fd == -1) {
			if (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		if (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos, NULL);
#ifdef __OpenBSD__
			if (ret == TLS_WANT_POLLIN)
				pfd[POLL_STDIN].events = POLLIN;
			else if (ret == TLS_WANT_POLLOUT)
				pfd[POLL_STDIN].events = POLLOUT;
			else if (ret == 0 || ret == -1)
#else
			if (ret == 0 || ret == -1)
#endif
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			if (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			if (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		if (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos, tls_ctx, FreeBSD_crlf);
#ifdef __OpenBSD__
			if (ret == TLS_WANT_POLLIN)
				pfd[POLL_NETOUT].events = POLLIN;
			else if (ret == TLS_WANT_POLLOUT)
				pfd[POLL_NETOUT].events = POLLOUT;
			else if (ret == -1)
#else
			if (ret == -1)
#endif
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			if (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			if (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		if (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos, tls_ctx);
#ifdef __OpenBSD__
			if (ret == TLS_WANT_POLLIN)
				pfd[POLL_NETIN].events = POLLIN;
			else if (ret == TLS_WANT_POLLOUT)
				pfd[POLL_NETIN].events = POLLOUT;
			else if (ret == -1)
#else
			if (ret == -1)
#endif
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			if (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			if (recvlimit > 0 && ++recvcount >= recvlimit) {
				if (pfd[POLL_NETIN].fd != -1)
					shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
				pfd[POLL_STDIN].fd = -1;
			}
			/* read something - poll stdout */
			if (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			if (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			if (pfd[POLL_NETIN].fd != -1 && tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		if (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos, NULL, 0);
#ifdef __OpenBSD__
			if (ret == TLS_WANT_POLLIN)
				pfd[POLL_STDOUT].events = POLLIN;
			else if (ret == TLS_WANT_POLLOUT)
				pfd[POLL_STDOUT].events = POLLOUT;
			else if (ret == -1)
#else
			if (ret == -1)
#endif
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			if (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			if (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		if (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			if (pfd[POLL_NETOUT].fd != -1 && Nflag) {
				if (FreeBSD_stats) {
					FreeBSD_stats_print(net_fd);
					stats_printed = 1;
				}
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			}
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		if (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
write_wrapper(int fd, const void *buf, size_t buflen)
{
	ssize_t n = write(fd, buf, buflen);
	/* don't treat EAGAIN, EINTR as error */
	return (n == -1 && (errno == EAGAIN || errno == EINTR)) ? -2 : n;
}

ssize_t
#ifdef __OpenBSD__
drainbuf(int fd, unsigned char *buf, size_t *bufpos, struct tls *tls)
#else
drainbuf(int fd, unsigned char *buf, size_t *bufpos, void *tls __unused, int crlf)
#endif
{
	ssize_t n = *bufpos, n2 = 0;
	ssize_t adjust;
	unsigned char *lf = NULL;

	if (fd == -1)
		return -1;

	if (crlf) {
		lf = memchr(buf, '\n', *bufpos);
		if (lf && (lf == buf || *(lf - 1) != '\r'))
			n = lf - buf;
		else
			lf = NULL;
	}

#ifdef __OpenBSD__
	if (tls) {
		n = tls_write(tls, buf, *bufpos);
		if (n == -1)
			errx(1, "tls write failed (%s)", tls_error(tls));
	} else {
		n = write(fd, buf, *bufpos);
		/* don't treat EAGAIN, EINTR as error */
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
			n = TLS_WANT_POLLOUT;
	}
	if (n <= 0)
		return n;
#else
	if (n != 0) {
		n = write_wrapper(fd, buf, n);
		if (n <= 0)
			return n;
	}

	if (lf) {
		n2 = write_wrapper(fd, "\r\n", 2);
		if (n2 <= 0)
			return n2;
		n += 1;
	}
#endif
	/* adjust buffer */
	adjust = *bufpos - n;
	if (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	return n;
}

ssize_t
#ifdef __OpenBSD__
fillbuf(int fd, unsigned char *buf, size_t *bufpos, struct tls *tls)
#else
fillbuf(int fd, unsigned char *buf, size_t *bufpos, void *tls __unused)
#endif
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	if (fd == -1)
		return -1;

#ifdef __OpenBSD__
	if (tls) {
		n = tls_read(tls, buf + *bufpos, num);
		if (n == -1)
			errx(1, "tls read failed (%s)", tls_error(tls));
	} else {
		n = read(fd, buf + *bufpos, num);
		/* don't treat EAGAIN, EINTR as error */
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
			n = TLS_WANT_POLLIN;
	}
#else
	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
#endif
	if (n <= 0)
		return n;
	*bufpos += n;
	return n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(int nfd)
{
	struct msghdr mh;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char c = '\0';
	ssize_t r;
	struct pollfd pfd;

	/* Avoid obvious stupidity */
	if (isatty(STDOUT_FILENO))
		errx(1, "Cannot pass file descriptor to tty");

	memset(&mh, 0, sizeof(mh));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	memset(&iov, 0, sizeof(iov));

	mh.msg_control = (caddr_t)&cmsgbuf.buf;
	mh.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = nfd;

	iov.iov_base = &c;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	for (;;) {
		r = sendmsg(STDOUT_FILENO, &mh, 0);
		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				if (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} else if (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		else
			break;
	}
	exit(0);
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(int nfd, unsigned char *buf, unsigned int size)
{
	unsigned char *p, *end;
	unsigned char obuf[4];

	if (size < 3)
		return;
	end = buf + size - 2;

	for (p = buf; p < end; p++) {
		if (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		if ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		else if ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		else
			continue;

		p++;
		obuf[2] = *p;
		if (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

int
strtoport(char *portstr, int udp)
{
	struct servent *entry;
	const char *errstr;
	char *proto;
	int port = -1;

	proto = udp ? "udp" : "tcp";

	port = strtonum(portstr, 1, PORT_MAX, &errstr);
	if (errstr == NULL)
		return port;
	if (errno != EINVAL)
		errx(1, "port number %s: %s", errstr, portstr);
	if ((entry = getservbyname(portstr, proto)) == NULL)
		errx(1, "service \"%s\" unknown", portstr);
	return ntohs(entry->s_port);
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void
build_ports(char *p)
{
	char *n;
	int hi, lo, cp;
	int x = 0;

	if (isdigit((unsigned char)*p) && (n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtoport(n, uflag);
		lo = strtoport(p, uflag);
		if (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/*
		 * Initialize portlist with a random permutation.  Based on
		 * Knuth, as in ip_randomid() in sys/netinet/ip_id.c.
		 */
		if (rflag) {
			for (x = 0; x <= hi - lo; x++) {
				cp = arc4random_uniform(x + 1);
				portlist[x] = portlist[cp];
				if (asprintf(&portlist[cp], "%d", x + lo) == -1)
					err(1, "asprintf");
			}
		} else { /* Load ports sequentially. */
			for (cp = lo; cp <= hi; cp++) {
				if (asprintf(&portlist[x], "%d", cp) == -1)
					err(1, "asprintf");
				x++;
			}
		}
	} else {
		char *tmp;

		hi = strtoport(p, uflag);
		if (asprintf(&tmp, "%d", hi) != -1)
			portlist[0] = tmp;
		else
			err(1, NULL);
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
int
udptest(int s)
{
	int i, ret;

	/* Only write to the socket in scan mode or interactive mode. */
	if (!zflag && !isatty(STDIN_FILENO))
		return 0;

	for (i = 0; i <= 3; i++) {
		if (write(s, "X", 1) == 1)
			ret = 1;
		else
			ret = -1;
	}
	return ret;
}

void
connection_info(const char *host, const char *port, const char *proto,
    const char *ipaddr)
{
	struct servent *sv;
	char *service = "*";

	/* Look up service name unless -n. */
	if (!nflag) {
		sv = getservbyport(ntohs(atoi(port)), proto);
		if (sv != NULL)
			service = sv->s_name;
	}

	fprintf(stderr, "Connection to %s", host);

	/*
	 * if we aren't connecting thru a proxy and
	 * there is something to report, print IP
	 */
	if (!nflag && !xflag && strcmp(host, ipaddr) != 0)
		fprintf(stderr, " (%s)", ipaddr);

	fprintf(stderr, " %s port [%s/%s] succeeded!\n", port, proto, service);
}

void
FreeBSD_stats_setup(int s)
{

	if (setsockopt(s, IPPROTO_TCP, TCP_STATS,
	    &FreeBSD_stats, sizeof(FreeBSD_stats)) == -1) {
		if (errno == EOPNOTSUPP) {
			warnx("getsockopt(TCP_STATS) failed; "
			    "kernel built without \"options STATS\"?");
		}
		err(1, "enable TCP_STATS gathering");
	}
}

void
FreeBSD_stats_print(int s)
{
#ifdef WITH_STATS
	struct statsblob *statsb;
	struct sbuf *sb;
	socklen_t sockoptlen;
	int error;

	/*
	 * This usleep is a workaround for TCP_STATS reporting
	 * incorrect values for TXPB.
	 */
	usleep(100000);

	sockoptlen = 2048;
	statsb = malloc(sockoptlen);
	if (statsb == NULL)
		err(1, "malloc");
	error = getsockopt(s, IPPROTO_TCP, TCP_STATS, statsb, &sockoptlen);
	if (error != 0) {
		if (errno == EOVERFLOW && statsb->cursz > sockoptlen) {
			/* Retry with a larger size. */
			sockoptlen = statsb->cursz;
			statsb = realloc(statsb, sockoptlen);
			if (statsb == NULL)
				err(1, "realloc");
			error = getsockopt(s, IPPROTO_TCP, TCP_STATS,
			    statsb, &sockoptlen);
		}
		if (error != 0)
			err(1, "getsockopt");
	}

	sb = sbuf_new_auto();
	error = stats_blob_tostr(statsb, sb, SB_STRFMT_JSON, SB_TOSTR_META);
	if (error != 0)
		errc(1, error, "stats_blob_tostr");

	error = sbuf_finish(sb);
	if (error != 0)
		err(1, "sbuf_finish");

	fprintf(stderr, "%s\n", sbuf_data(sb));
#endif
}

void
set_common_sockopts(int s, int af)
{
	int x = 1;

	if (Sflag) {
		if (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
		    &x, sizeof(x)) == -1)
			err(1, NULL);
	}
	if (Dflag) {
		if (setsockopt(s, SOL_SOCKET, SO_DEBUG,
		    &x, sizeof(x)) == -1)
			err(1, NULL);
	}
	if (Tflag != -1) {
		if (af == AF_INET && setsockopt(s, IPPROTO_IP,
		    IP_TOS, &Tflag, sizeof(Tflag)) == -1)
			err(1, "set IP ToS");

		else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6,
		    IPV6_TCLASS, &Tflag, sizeof(Tflag)) == -1)
			err(1, "set IPv6 traffic class");
	}
	if (Iflag) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, sizeof(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	if (Oflag) {
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, sizeof(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
	if (FreeBSD_Oflag) {
		if (setsockopt(s, IPPROTO_TCP, TCP_NOOPT,
		    &FreeBSD_Oflag, sizeof(FreeBSD_Oflag)) == -1)
			err(1, "disable TCP options");
	}
	if (FreeBSD_stats)
		FreeBSD_stats_setup(s);
#ifdef IPSEC
	if (ipsec_policy[0] != NULL)
		add_ipsec_policy(s, af, ipsec_policy[0]);
	if (ipsec_policy[1] != NULL)
		add_ipsec_policy(s, af, ipsec_policy[1]);
#endif

	if (ttl != -1) {
		if (af == AF_INET && setsockopt(s, IPPROTO_IP,
		    IP_TTL, &ttl, sizeof(ttl)))
			err(1, "set IP TTL");

		else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6,
		    IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)))
			err(1, "set IPv6 unicast hops");
	}

	if (minttl != -1) {
		if (af == AF_INET && setsockopt(s, IPPROTO_IP,
		    IP_MINTTL, &minttl, sizeof(minttl)))
			err(1, "set IP min TTL");

#ifdef __OpenBSD__
		else if (af == AF_INET6 && setsockopt(s, IPPROTO_IPV6,
		    IPV6_MINHOPCOUNT, &minttl, sizeof(minttl)))
			err(1, "set IPv6 min hop count");
#else
		else if (af == AF_INET6)
			warn("Unable to set IPv6 min hop count");
#endif
	}
}

int
process_tos_opt(char *s, int *val)
{
	/* DiffServ Codepoints and other TOS mappings */
	const struct toskeywords {
		const char	*keyword;
		int		 val;
	} *t, toskeywords[] = {
		{ "af11",		IPTOS_DSCP_AF11 },
		{ "af12",		IPTOS_DSCP_AF12 },
		{ "af13",		IPTOS_DSCP_AF13 },
		{ "af21",		IPTOS_DSCP_AF21 },
		{ "af22",		IPTOS_DSCP_AF22 },
		{ "af23",		IPTOS_DSCP_AF23 },
		{ "af31",		IPTOS_DSCP_AF31 },
		{ "af32",		IPTOS_DSCP_AF32 },
		{ "af33",		IPTOS_DSCP_AF33 },
		{ "af41",		IPTOS_DSCP_AF41 },
		{ "af42",		IPTOS_DSCP_AF42 },
		{ "af43",		IPTOS_DSCP_AF43 },
		{ "critical",		IPTOS_PREC_CRITIC_ECP },
		{ "cs0",		IPTOS_DSCP_CS0 },
		{ "cs1",		IPTOS_DSCP_CS1 },
		{ "cs2",		IPTOS_DSCP_CS2 },
		{ "cs3",		IPTOS_DSCP_CS3 },
		{ "cs4",		IPTOS_DSCP_CS4 },
		{ "cs5",		IPTOS_DSCP_CS5 },
		{ "cs6",		IPTOS_DSCP_CS6 },
		{ "cs7",		IPTOS_DSCP_CS7 },
		{ "ef",			IPTOS_DSCP_EF },
		{ "inetcontrol",	IPTOS_PREC_INTERNETCONTROL },
		{ "lowdelay",		IPTOS_LOWDELAY },
		{ "netcontrol",		IPTOS_PREC_NETCONTROL },
		{ "reliability",	IPTOS_RELIABILITY },
		{ "throughput",		IPTOS_THROUGHPUT },
		{ NULL,			-1 },
	};

	for (t = toskeywords; t->keyword != NULL; t++) {
		if (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			return 1;
		}
	}

	return 0;
}

#ifdef __OpenBSD__
int
process_tls_opt(char *s, int *flags)
{
	size_t len;
	char *v;

	const struct tlskeywords {
		const char	*keyword;
		int		 flag;
		char		**value;
	} *t, tlskeywords[] = {
		{ "ciphers",		-1,			&tls_ciphers },
		{ "clientcert",		TLS_CCERT,		NULL },
		{ "muststaple",		TLS_MUSTSTAPLE,		NULL },
		{ "noverify",		TLS_NOVERIFY,		NULL },
		{ "noname",		TLS_NONAME,		NULL },
		{ "protocols",		-1,			&tls_protocols },
		{ NULL,			-1,			NULL },
	};

	len = strlen(s);
	if ((v = strchr(s, '=')) != NULL) {
		len = v - s;
		v++;
	}

	for (t = tlskeywords; t->keyword != NULL; t++) {
		if (strlen(t->keyword) == len &&
		    strncmp(s, t->keyword, len) == 0) {
			if (t->value != NULL) {
				if (v == NULL)
					errx(1, "invalid tls value `%s'", s);
				*t->value = v;
			} else {
				*flags |= t->flag;
			}
			return 1;
		}
	}
	return 0;
}

void
save_peer_cert(struct tls *tls_ctx, FILE *fp)
{
	const char *pem;
	size_t plen;

	if ((pem = tls_peer_cert_chain_pem(tls_ctx, &plen)) == NULL)
		errx(1, "Can't get peer certificate");
	if (fprintf(fp, "%.*s", (int)plen, pem) < 0)
		err(1, "unable to save peer cert");
	if (fflush(fp) != 0)
		err(1, "unable to flush peer cert");
}

void
report_tls(struct tls *tls_ctx, char *host)
{
	time_t t;
	const char *ocsp_url;

	fprintf(stderr, "TLS handshake negotiated %s/%s with host %s\n",
	    tls_conn_version(tls_ctx), tls_conn_cipher(tls_ctx), host);
	fprintf(stderr, "Peer name: %s\n",
	    tls_expectname ? tls_expectname : host);
	if (tls_peer_cert_subject(tls_ctx))
		fprintf(stderr, "Subject: %s\n",
		    tls_peer_cert_subject(tls_ctx));
	if (tls_peer_cert_issuer(tls_ctx))
		fprintf(stderr, "Issuer: %s\n",
		    tls_peer_cert_issuer(tls_ctx));
	if ((t = tls_peer_cert_notbefore(tls_ctx)) != -1)
		fprintf(stderr, "Valid From: %s", ctime(&t));
	if ((t = tls_peer_cert_notafter(tls_ctx)) != -1)
		fprintf(stderr, "Valid Until: %s", ctime(&t));
	if (tls_peer_cert_hash(tls_ctx))
		fprintf(stderr, "Cert Hash: %s\n",
		    tls_peer_cert_hash(tls_ctx));
	ocsp_url = tls_peer_ocsp_url(tls_ctx);
	if (ocsp_url != NULL)
		fprintf(stderr, "OCSP URL: %s\n", ocsp_url);
	switch (tls_peer_ocsp_response_status(tls_ctx)) {
	case TLS_OCSP_RESPONSE_SUCCESSFUL:
		fprintf(stderr, "OCSP Stapling: %s\n",
		    tls_peer_ocsp_result(tls_ctx) == NULL ? "" :
		    tls_peer_ocsp_result(tls_ctx));
		fprintf(stderr,
		    "  response_status=%d cert_status=%d crl_reason=%d\n",
		    tls_peer_ocsp_response_status(tls_ctx),
		    tls_peer_ocsp_cert_status(tls_ctx),
		    tls_peer_ocsp_crl_reason(tls_ctx));
		t = tls_peer_ocsp_this_update(tls_ctx);
		fprintf(stderr, "  this update: %s",
		    t != -1 ? ctime(&t) : "\n");
		t = tls_peer_ocsp_next_update(tls_ctx);
		fprintf(stderr, "  next update: %s",
		    t != -1 ? ctime(&t) : "\n");
		t = tls_peer_ocsp_revocation_time(tls_ctx);
		fprintf(stderr, "  revocation: %s",
		    t != -1 ? ctime(&t) : "\n");
		break;
	case -1:
		break;
	default:
		fprintf(stderr,
		    "OCSP Stapling:  failure - response_status %d (%s)\n",
		    tls_peer_ocsp_response_status(tls_ctx),
		    tls_peer_ocsp_result(tls_ctx) == NULL ? "" :
		    tls_peer_ocsp_result(tls_ctx));
		break;
	}
}
#endif

void
report_sock(const char *msg, const struct sockaddr *sa, socklen_t salen,
    char *path)
{
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int herr;
	int flags = NI_NUMERICSERV;

	if (path != NULL) {
		fprintf(stderr, "%s on %s\n", msg, path);
		return;
	}

	if (nflag)
		flags |= NI_NUMERICHOST;

	herr = getnameinfo(sa, salen, host, sizeof(host), port, sizeof(port),
	    flags);
	switch (herr) {
	case 0:
		break;
	case EAI_SYSTEM:
		err(1, "getnameinfo");
	default:
		errx(1, "getnameinfo: %s", gai_strerror(herr));
	}

	fprintf(stderr, "%s on %s %s\n", msg, host, port);
}

void
help(void)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t--crlf	Convert LF into CRLF when sending data over the network\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n");
#ifdef IPSEC
	fprintf(stderr, "\
	\t-E		Use IPsec ESP\n\
	\t-e policy	Use specified IPsec policy\n");
#endif
	fprintf(stderr, "\
	\t-F		Pass socket fd\n\
	\t-h		This help text\n\
	\t-I length	TCP receive buffer length\n\
	\t-i interval	Delay interval for lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open for multiple connects\n\
	\t-l		Listen mode, for inbound connects\n\
	\t-M ttl		Outgoing TTL / Hop Limit\n\
	\t-m minttl	Minimum incoming TTL / Hop Limit\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t--no-tcpopt	Disable TCP options\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername for proxy authentication\n\
	\t-p port\t	Specify local port for remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s sourceaddr	Local source address\n\
	\t--sctp\t	SCTP mode\n\
	\t--stats	Report TCP_STATS via the stats(3) interface\n\
	\t-T keyword	TOS value or TLS options\n\
	\t-t		Answer TELNET negotiation\n\
	\t--tun tundev	Use tun device rather than stdio\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V FIB	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-W recvlimit	Terminate after receiving a number of packets\n\
	\t-w timeout	Timeout for connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used for scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
#ifdef IPSEC
	fprintf(stderr, "\tSee ipsec_set_policy(3) for -e argument format\n");
#endif
	exit(1);
}

#ifdef IPSEC
void
add_ipsec_policy(int s, int af, char *policy)
{
	char *raw;
	int e;

	raw = ipsec_set_policy(policy, strlen(policy));
	if (raw == NULL)
		errx(1, "ipsec_set_policy `%s': %s", policy,
		     ipsec_strerror());
	if (af == AF_INET)
		e = setsockopt(s, IPPROTO_IP, IP_IPSEC_POLICY, raw,
		    ipsec_get_policylen(raw));
	if (af == AF_INET6)
		e = setsockopt(s, IPPROTO_IPV6, IPV6_IPSEC_POLICY, raw,
		    ipsec_get_policylen(raw));
	if (e < 0)
		err(1, "ipsec policy cannot be configured");
	free(raw);
	if (vflag)
		fprintf(stderr, "ipsec policy configured: `%s'\n", policy);
	return;
}
#endif /* IPSEC */

void
usage(int ret)
{
	fprintf(stderr,
#ifdef IPSEC
	    "usage: nc [-46DdEFhklNnrStUuvz] [--crlf] [-e policy] [-I length] [-i interval]\n"
#else
	    "usage: nc [-46DdFhklNnrStUuvz] [--crlf] [-I length] [-i interval]\n"
#endif
	    "\t  [-M ttl] [-m minttl] [--no-tcpopt] [-O length] [-P proxy_username]\n"
	    "\t  [-p source_port] [-s sourceaddr] [--sctp] [--stats] [-T ToS]\n"
	    "\t  [--tun tundev] [-V FIB] [-W recvlimit] [-w timeout]\n"
	    "\t  [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]\n");
	if (ret)
		exit(1);
}
