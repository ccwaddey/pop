/*
 * Copyright (c) 2021 Chris Waddey <admin@hoolizen.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "imsgpop.h"

struct tls_config	*tlsconf;
struct tls		*maintls;
struct event		 rootev;
struct event		 rootwev;
struct imsgbuf		 rootimb;
/* Before logging in, only 30 seconds to login. Once logged in, you
 * get 11 minutes before automatically disconnected. */
struct timeval		 ssntimeout = {(time_t)60*11, 0};
struct timeval		 logintimeout = {(time_t)30, 0};

static void handlerootread(int, short, void *);
static void handlerootwrite(int, short, void *);
static void wrkrimsgread(int, short, void *);
static void wrkrimsgwrite(int, short, void *);
static void handlenewconn(int);
static void writebuffertls(int, short, void *);
static void handlenewuser(struct imsg *);
static void killssn(int, short, void *);

static unsigned long newpeerid(void);

struct io {
	struct event	 io_ev;
	ssize_t		 io_buflen;
	ssize_t		 io_bufoff;
	char		 io_buf[IOBUFLEN];
	uint8_t		 io_ssntype;
	void		*io_ssn;
	void		(*io_cb)(struct io *);
};

enum {	IO_AUTHSSN = 1,
	IO_IOSSN,
};

static void greet2username(struct io *);
static void handleusername(struct io *);
static void username2password(struct io *);
static void handlepassword(struct io *);
static void sendresp(struct io *, int, void (*)(struct io *), const char *);
static void recvcomm(struct io *, void (*)(struct io *));
static void killssncb(struct io *);
static void send2wrkr(struct io *);
static void recv2wrkr(struct io *);
static void clearima(struct io *);
static void wrkrimsgrdcb(struct io *);

/* This is for sessions before they have logged in */
struct iossn {
	RB_ENTRY(iossn)	 ios_tree;
	unsigned long	 ios_peerid;
	int		 ios_sock;
	struct tls	*ios_tls;
	struct event	 ios_timeev;
	struct timeval	 ios_timeval;
	struct io	*ios_iop;
	struct imsgauth	 ios_ima;
};

/* This is for sessions that have been logged in */
struct authssn {
	struct imsgbuf		 as_imb; /* doubles as ptr to authssn */
	RB_ENTRY(authssn)	 as_tree;
	uint8_t			 as_flags;
	int			 as_clntsd;
	int			 as_wrkrsd;
	struct tls		*as_tls;
	struct event		 as_timeev;
	struct timeval		 as_timeval;
	struct io		*as_iop;
	char		 	 as_user[MAXARGLEN + 1];
};

#define ASF_GOAHEAD	1
#define ASF_GETMORE	2

static void ssntimerreset(struct authssn *);

static int
iossncmp(struct iossn *a, struct iossn *b) {
	if (a->ios_peerid < b->ios_peerid)
		return -1;
	else
		return (a->ios_peerid > b->ios_peerid);
}

RB_HEAD(iotr, iossn) iossnhead = RB_INITIALIZER(&iossnhead);
RB_PROTOTYPE_STATIC(iotr, iossn, ios_tree, iossncmp)
RB_GENERATE_STATIC(iotr, iossn, ios_tree, iossncmp)

static int
authssncmp(struct authssn *a1, struct authssn *a2) {
	return strcmp(a1->as_user, a2->as_user);
}

RB_HEAD(authnmtr, authssn) authssnhead = RB_INITIALIZER(&authssnhead);
RB_PROTOTYPE_STATIC(authnmtr, authssn, as_tree, authssncmp)
RB_GENERATE_STATIC(authnmtr, authssn, as_tree, authssncmp)	

int
main(int argc, char *argv[]) {

	/* printf("%s\n%s\n", argv[2], argv[3]); */
	if ((tlsconf = tls_config_new()) == NULL)
		errx(1, "tls_config_new: %s", tls_config_error(tlsconf));

	if (tls_config_set_protocols(tlsconf, TLS_PROTOCOL_TLSv1_3))
		errx(1, "tls_config_set_protocols: %s",
		    tls_config_error(tlsconf));
	if (tls_config_set_cert_file(tlsconf, argv[1]))
		errx(1, "tls_config_set_cert_file: %s",
		    tls_config_error(tlsconf));
	if (tls_config_set_key_file(tlsconf, argv[2]))
		errx(1, "tls_config_set_key_file: %s",
		    tls_config_error(tlsconf));
	if ((maintls = tls_server()) == NULL)
		errx(1, "tls_server: %s", tls_error(maintls));
	if (tls_configure(maintls, tlsconf))
		errx(1, "tls_configure: %s", tls_error(maintls));
	tls_config_free(tlsconf);

	closefrom(4); /* Don't worry about EINTR b/c no handle sigs */

	/* should |= these flags but all other opts aren't important */
	if (fcntl(3, F_SETFL, O_NONBLOCK) == -1)
		errx(1, "could not set nonblocking unix socket");
	imsg_init(&rootimb, 3);
	/* Okay now the tls config is set, unneeded fds are closed,
	 * and imsg_init is done. */
	if (chroot("/var/empty"))
		err(1, "chroot");
	if (chdir("/"))
		err(1, "chdir");
	/* change to a very restricted user here; need lots of fds */
	/* Pledge something here. We only need to read and write from
	 * a unix socket and an internet socket. */
	event_init();

	/* We always want to know if root has something for us */
	event_set(&rootwev, rootimb.fd, EV_WRITE, handlerootwrite, &rootimb);
	event_set(&rootev, rootimb.fd, EV_READ | EV_PERSIST, handlerootread,
	    &rootimb);
	if (event_add(&rootev, NULL) == -1)
		err(1, "event_add");

	event_dispatch();
}

static void
readbuffertls(int fd, short event, void *arg) {
	struct io	*iop;
	struct tls	*tlsp;
	ssize_t		 retval;

	iop = arg;
	if (iop->io_ssntype == IO_AUTHSSN)
		tlsp = ((struct authssn *)iop->io_ssn)->as_tls;
	else if (iop->io_ssntype == IO_IOSSN)
		tlsp = ((struct iossn *)iop->io_ssn)->ios_tls;
	else
		errx(1, "invalid io_ssn type");

	retval = tls_read(tlsp, &iop->io_buf[iop->io_bufoff],
	    iop->io_buflen - iop->io_bufoff);
	if (retval == -1) {
		killssn(0, 0, iop);
		return;
	} else if (retval == TLS_WANT_POLLIN) {
		event_set(&iop->io_ev, fd, EV_READ, readbuffertls, iop);
		event_add(&iop->io_ev, NULL);
		return;
	} else if (retval == TLS_WANT_POLLOUT) {
		event_set(&iop->io_ev, fd, EV_WRITE, readbuffertls, iop);
		event_add(&iop->io_ev, NULL);
		return;
	} else {
		iop->io_bufoff += retval;
		if (iop->io_bufoff == iop->io_buflen ||
		    (iop->io_bufoff < iop->io_buflen &&
		    memchr(iop->io_buf, '\n', iop->io_bufoff))) {
			/* We have a potentially valid line. Worth
			 * noting that when we call the callback,
			 * io_bufoff is the length of data read, also
			 * that this function does not read more
			 * than io_buflen bytes into io_buf. */
			if (iop->io_cb == NULL)
				errx(1, "bad callback");
			/* xundo */
			/* printf("%s", iop->io_buf); */
			iop->io_cb(iop);
			return;
		} else if (iop->io_bufoff < iop->io_buflen) {
			event_set(&iop->io_ev, fd, EV_READ,
			    readbuffertls, iop);
			event_add(&iop->io_ev, NULL);
			return;
		} else
			errx(1, "readtls");
	}
}

static void
writebuffertls(int fd, short event, void *arg) {
	struct io	*iop;
	struct tls	*tlsp;
	ssize_t		 retval;

	iop = arg;
	if (iop->io_ssntype == IO_AUTHSSN)
		tlsp = ((struct authssn *)iop->io_ssn)->as_tls;
	else if (iop->io_ssntype == IO_IOSSN)
		tlsp = ((struct iossn *)iop->io_ssn)->ios_tls;
	else
		errx(1, "invalid io_ssn type");
		
	retval = tls_write(tlsp, &iop->io_buf[iop->io_bufoff],
	    iop->io_buflen - iop->io_bufoff);
	if (retval == -1) { /* error, shutdown ssn */
		killssn(0, 0, iop);
		return;
	} else if (retval == TLS_WANT_POLLIN) {
		event_set(&iop->io_ev, fd, EV_READ, writebuffertls, iop);
		event_add(&iop->io_ev, NULL);
		return;
	} else if (retval == TLS_WANT_POLLOUT) {
		event_set(&iop->io_ev, fd, EV_WRITE, writebuffertls, iop);
		event_add(&iop->io_ev, NULL);
		return;
	} else {
		iop->io_bufoff += retval;
		if (iop->io_bufoff < iop->io_buflen) {
			event_set(&iop->io_ev, fd, EV_WRITE,
			    writebuffertls, iop);
			event_add(&iop->io_ev, NULL);
			return;
		} else if (iop->io_bufoff == iop->io_buflen) {
			if (iop->io_cb != NULL)
				iop->io_cb(iop);
			return;
		} else
			errx(1, "writetls");
	}
}

static void
handlerootread(int fd, short event, void *arg) {
	struct imsgbuf	*imbp;
	struct imsg	 im;
	ssize_t		 n;

	imbp = arg;
	if ((n = imsg_read(imbp)) == -1) {
		if (errno == EAGAIN)
			return;
		errx(1, "imsg_read");
	}
	if (n == 0)
		exit(2); /* root died */

	for (;;) {
		if ((n = imsg_get(imbp, &im)) == -1)
			err(1, "imsg_get");
		if (n == 0)
			return;

		switch (im.hdr.type) {
		case APRT_NEW_CONN:
			handlenewconn(im.fd);
			break;
		case APRT_NEW_USER:
			handlenewuser(&im);
			break;
		default:
			errx(1, "invalid imsg type");
			break;
		}

		imsg_free(&im);
	}
}

static void
handlerootwrite(int fd, short event, void *arg) {
	struct imsgbuf	*imbp;
	int		 n;

	imbp = arg;
	if (!imbp->w.queued)
		return;

	if ((n = msgbuf_write(&imbp->w)) == -1 && errno == EAGAIN)
		goto add;

	if (n == -1)
		err(1, "msgbuf_write");

	/* don't write anything but had something to write means root
	 * died */
	if (n == 0)
		exit(2);

	if (imbp->w.queued)
		goto add;
	return;
add:
	if (event_add(&rootwev, NULL))
		err(1, "event_add");
}

static void
wrkrimsgrdcb(struct io *iop) {
	struct authssn	*asp;

	if (iop->io_ssntype != IO_AUTHSSN)
		errx(1, "io_ssntype");

	asp = iop->io_ssn;
	if (asp->as_flags & ASF_GETMORE) {
		wrkrimsgread(-1, -1, iop);
		return;
	}
	event_set(&iop->io_ev, asp->as_wrkrsd, EV_READ, wrkrimsgread, iop);
	if (event_add(&iop->io_ev, NULL))
		killssncb(iop);
	return;
}

static void
wrkrimsgread(int fd, short event, void *arg) {
	struct authssn	*asp;
	struct imsgbuf	*imbp;
	struct imsg	 myimsg;
	struct io	*iop;
	ssize_t		 n;

	iop = arg;
	asp = iop->io_ssn;
	imbp = &asp->as_imb;
	if (!(asp->as_flags & ASF_GETMORE)) {
		if ((n = imsg_read(imbp)) == -1) {
			if (errno == EAGAIN)
				return;
			err(1, "imsg_read");
		}
		if (!n)
			killssncb(iop);
		/* All good on the read, set the getmore flag */
		asp->as_flags &= ASF_GETMORE;
	}

	if ((n = imsg_get(imbp, &myimsg)) == -1)
		err(1, "imsg_get");
	if (n == 0) {
		asp->as_flags &= ~ASF_GETMORE;
		wrkrimsgrdcb(iop); /* Just sets up event reading for us */
		return;
	}

	switch (myimsg.hdr.type) {
	case WRKR_DATA:
		sendresp(iop, S_EMPTY, wrkrimsgrdcb,
		    (const char *)myimsg.data);
		break;
	case WRKR_DATA_END:
		asp->as_flags &= ~ASF_GETMORE;
		sendresp(iop, S_EMPTY, recv2wrkr,
		    (const char *)myimsg.data);
		break;
	case WRKR_END:
		sendresp(iop, S_EMPTY, killssncb,
		    (const char *)myimsg.data);
		break;
	default:
		errx(1, "invalid imsg type");
		break;
	}

	imsg_free(&myimsg);

}

static void
wrkrimsgwrite(int fd, short event, void *arg) {
	struct authssn	*asp;
	struct imsgbuf	*imbp;
	struct io	*iop;
	int		 n;

	iop = arg;
	asp = iop->io_ssn;
	imbp = &asp->as_imb;
	if (!imbp->w.queued)
		goto err;

	if ((n = msgbuf_write(&imbp->w)) == -1 && errno == EAGAIN)
		goto again;
	
	if (n == -1 || n == 0)
		goto err;
	/* We don't want to send more than one imsg */
	/* if (imbp->w.queued) */
	/* 	goto again; */
	if (asp->as_flags & ASF_GOAHEAD) {
		asp->as_flags &= ~ASF_GOAHEAD;
		sendresp(iop, S_OK, recv2wrkr, "authenticated");
		return;
	}
	event_set(&iop->io_ev, asp->as_wrkrsd, EV_READ, wrkrimsgread, iop);
again:
	if (event_add(&iop->io_ev, NULL))
		goto err;
	return;
err:
	killssncb(iop);
	return;
}

static void
recv2wrkr(struct io *iop) {
	recvcomm(iop, send2wrkr);
	
	return;
}

static void
send2wrkr(struct io *iop) {
	struct authssn	*asp;
	int		 rv;

	asp = iop->io_ssn;
	ssntimerreset(asp);
	rv = imsg_compose(&asp->as_imb, WRKR_DATA, 0, 0, -1, iop->io_buf,
	    iop->io_bufoff + 1);
	if (rv == -1) {
		killssncb(iop);
		return;
	}
	event_set(&iop->io_ev, asp->as_wrkrsd, EV_WRITE, wrkrimsgwrite, iop);
	if (event_add(&iop->io_ev, NULL))
		killssncb(iop);
	return;
}

/* This should really be called "setup_ev_to_send_resp" */
static void
sendresp(struct io *iop, int scode, void (*cb)(struct io *), const char *cp) {
	static const char	*rs[S_NUMRS] = { "+OK ", "-ERR ", ""};
	int			 sd;
	
	explicit_bzero(iop->io_buf, sizeof iop->io_buf);
	if (scode < 0 || scode >= S_NUMRS)
		errx(1, "scode"); /* true error */
	iop->io_bufoff = 0;
	iop->io_buflen = snprintf(iop->io_buf, sizeof iop->io_buf,
	    "%s%s\r\n", rs[scode], cp);
	if (iop->io_buflen < 0 || iop->io_buflen >= sizeof iop->io_buf)
		err(1, "sendresp snprintf"); /* true error */

	iop->io_cb = cb;

	if (iop->io_ssntype == IO_IOSSN)
		sd = ((struct iossn *)iop->io_ssn)->ios_sock;
	else if (iop->io_ssntype == IO_AUTHSSN)
		sd = ((struct authssn *)iop->io_ssn)->as_clntsd;
	else
		errx(1, "send resp bad ssn type"); /* yeah, real error */
	event_set(&iop->io_ev, sd, EV_WRITE, writebuffertls, iop);
	if (event_add(&iop->io_ev, NULL))
		killssncb(iop);

	return;
}

/* Similarly, this should be called something like
 * "setup_ev_to_read_comm" */
static void
recvcomm(struct io *iop, void (*cb)(struct io *)) {
	int sock;
	
	explicit_bzero(iop->io_buf, sizeof iop->io_buf);
	iop->io_buflen = MAXINPUTLEN;
	iop->io_bufoff = 0;

	iop->io_cb = cb;

	if (iop->io_ssntype == IO_AUTHSSN)
		sock = ((struct authssn *)iop->io_ssn)->as_clntsd;
	else if (iop->io_ssntype == IO_IOSSN)
		sock = ((struct iossn *)iop->io_ssn)->ios_sock;
	else
		errx(1, "recvcomm ssntype");
	event_set(&iop->io_ev, sock, EV_READ, readbuffertls, iop);
	if (event_add(&iop->io_ev, NULL))
		killssncb(iop);

	return;
}

/* This is called after the root proc has sent us a socket for
 * connection. */
static void
handlenewconn(int sockd) {
	struct iossn	*iosp;
	struct io	*iop;

	/* We need to set the sockd to be non-blocking */
	if (fcntl(sockd, F_SETFL, O_NONBLOCK) == -1)
		goto err;
	/* if either of these two fail, we just return, no harm no foul. */
	/* calloc_conceal keeps plaintext passwords from ios_ima out
	 * of core dumps; also, io_buf can have passwords in them too,
	 * so calloc_conceal that as well. */
	if ((iosp = calloc_conceal(1, sizeof *iosp)) == NULL)
		goto err;
	if ((iop = calloc_conceal(1, sizeof *iop)) == NULL) {
		free(iosp);
		goto err;
	}
	/* setup iosp */
	iosp->ios_peerid = newpeerid();
	iosp->ios_sock = sockd;
	/* should we really error here or abort the nascent session?
	 * Let's error, better safe than sorry. */
	if (tls_accept_socket(maintls, &iosp->ios_tls, sockd))
		errx(1, "tls_accept_socket");

	iosp->ios_iop = iop;
	iosp->ios_timeval.tv_sec = time(NULL);
	timeradd(&logintimeout, &iosp->ios_timeval, &iosp->ios_timeval);
	/* You get 30 seconds to login. If not, you're gone. This
	 * isn't rfc1939 compliant, but helps against DOS attacks. */
	evtimer_set(&iosp->ios_timeev, killssn, iop);
	evtimer_add(&iosp->ios_timeev, &iosp->ios_timeval);
	if (RB_INSERT(iotr, &iossnhead, iosp) != NULL)
		/* really an error, two eq peerid's. Technically, it
		 * could wrap, but that would take a long-ass time. */
		errx(1, "RB_INSERT");
	/* setup iop */
	/* iop->io_cb = &greet2username; */
	iop->io_ssntype = IO_IOSSN;
	iop->io_ssn = iosp;
	sendresp(iop, S_OK, greet2username, "popd ready");
	return;
err:
	if (close(sockd)) /* no signals so a real error */
		err(1, "close");
	return;
}

static void
greet2username(struct io *iop) {
	recvcomm(iop, handleusername);

	return;
}

static void
handleusername(struct io *iop) {
	struct iossn	*iosp;
	size_t		 rv, namelen;
	char		*cp;

	/* "USER", sp, one char user name, crlf = 4+1+1+2 = 8*/
	if (iop->io_bufoff < 8) {
		sendresp(iop, S_ERR, greet2username, "command too short");
		return;
	}
	if (iop->io_buf[iop->io_bufoff - 1] != '\n' ||
	    iop->io_buf[iop->io_bufoff - 2] != '\r') {
		sendresp(iop, S_ERR, greet2username, "expected crlf to end");
		return;
	}
	if (strncasecmp(iop->io_buf, "quit", 4) == 0) {
		sendresp(iop, S_OK, killssncb, "bye");
		return;
	}
	
	if (strncasecmp(iop->io_buf, "user", 4) != 0) {
		sendresp(iop, S_ERR, greet2username,
		    "expected user or quit command");
		return;
	}
	if (iop->io_buf[4] != ' ') {
		sendresp(iop, S_ERR, greet2username, "expected space");
		return;
	}

	cp = &iop->io_buf[5];
	while (islower(*cp) || isdigit(*cp))
		++cp;
	*cp = '\0';
	namelen = strlen(&iop->io_buf[5]);
	/* printf("handleusername: %s, %zu\n", &iop->io_buf[5], namelen); */
	/* fflush(stdout); */
	iosp = iop->io_ssn;
	if (cp == &iop->io_buf[iop->io_bufoff - 2]) {
		/* user, sp, \r\n = 7 + 1 for the \0 */
		rv = strlcpy(iosp->ios_ima.ima_userbuf, &iop->io_buf[5],
		    namelen + 1);
		if (rv >= namelen + 1)
			errx(1, "strlcpy in handleusername");
	} else {
		iosp->ios_ima.ima_prefail = 1;
		strcpy(iosp->ios_ima.ima_userbuf, "fakeuser");
	}

	/* Now set up next event */
	sendresp(iop, S_OK, username2password, "continue with PASS command");
}

static void
username2password(struct io *iop) {
	recvcomm(iop, handlepassword);
	
	return;
}

static void
handlepassword(struct io *iop) {
	struct iossn	*iosp;
	char		*cp;
	size_t		 passlen;
	int		 rv;

	if (iop->io_bufoff < 8) {
		clearima(iop);
		sendresp(iop, S_ERR, greet2username, "command too short");
		return;
	}
	if (iop->io_buf[iop->io_bufoff - 1] != '\n' ||
	    iop->io_buf[iop->io_bufoff - 2] != '\r') {
		clearima(iop);
		sendresp(iop, S_ERR, greet2username, "expected crlf to end");
		return;
	}
	if (!strncasecmp(iop->io_buf, "quit", 4)) {
		sendresp(iop, S_OK, killssncb, "bye");
		return;
	}
	if (strncasecmp(iop->io_buf, "pass", 4)) {
		clearima(iop);
		sendresp(iop, S_ERR, greet2username, "expected PASS command");
		return;
	}
	if (iop->io_buf[4] != ' ') {
		clearima(iop);
		sendresp(iop, S_ERR, greet2username, "expected space");
		return;
	}

	cp = &iop->io_buf[5];
	while (isprint(*cp))
		++cp;
	/* we should have a way to err w/o giving info */
	iosp = iop->io_ssn;
	if (cp != &iop->io_buf[iop->io_bufoff - 2]) {
		iosp->ios_ima.ima_prefail = 1;
		strcpy(iosp->ios_ima.ima_passbuf, "fakepass");
	} else {
		passlen = iop->io_bufoff - 7;
		/* Move password to ios_up */
		strlcpy(iosp->ios_ima.ima_passbuf, &iop->io_buf[5], passlen + 1);
	}
	/* explicitly clear password from io_buf once it's in
	 * ima_passbuf. This would be done when we send the response
	 * anyway, but be paranoid */
	explicit_bzero(iop->io_buf, sizeof iop->io_buf);
	/* Check if user is in authssnhead - do after */
	/* Construct imsg with peerid and up */
	rv = imsg_compose(&rootimb, APRT_NEW_USER, iosp->ios_peerid, 0, -1,
	    &iosp->ios_ima, sizeof iosp->ios_ima);
	if (rv == -1) {
		/* this is prob fatal, but we try to stay alive */
		killssncb(iop);
		return;
	}
	/* explicitly clear plaintext password out of memory as soon
	 * as imsg API has it, but leave username for
	 * handlenewuser(). */
	explicit_bzero(iosp->ios_ima.ima_passbuf,
	    sizeof(iosp->ios_ima.ima_passbuf));
	/* set rootwev for rootimb.fd writable */
	if (!event_pending(&rootwev, EV_WRITE, NULL))
		if (event_add(&rootwev, NULL)) {
			killssncb(iop);
			return;
		}
	/* They've submitted a password, but keep the login timeout in
	 * case we fork the wrkr but have an error during sendsock. */
}

static void
handlenewuser(struct imsg *imp) {
	struct io	*iop;
	struct iossn	*iosp, myios;
	struct authssn	*asp, myas;
	int		 rv, zero = 0;

	/* Get the user this imsg is for and remove the login timer. */
	myios.ios_peerid = imp->hdr.peerid;
	if ((iosp = RB_FIND(iotr, &iossnhead, &myios)) == NULL)
		errx(1, "fatal iotr find");
	iop = iosp->ios_iop;
	evtimer_del(&iosp->ios_timeev);

	/* The username and password didn't match, or some other error
	 * happened */
	if (imp->fd == -1) {
		sendresp(iop, S_ERR, killssncb, "bye");
		return;
	}

	/* Make sure no session already active, and some error checking. */
        strlcpy(myas.as_user, iosp->ios_ima.ima_userbuf, MAXARGLEN + 1);
	if (strncmp(imp->data, myas.as_user, MAXARGLEN + 1) != 0)
		errx(1, "strings not equal");
	if (RB_FIND(authnmtr, &authssnhead, &myas)) {
		if (close(imp->fd))
			err(1, "close");
		sendresp(iop, S_ERR, killssncb, "could not acquire lock");
		return;
	}

	/* Setup asp and free iosp */
	asp = calloc(1, sizeof *asp);
	if (!asp) {
		killssncb(iop);
		return;
	}
	asp->as_clntsd = iosp->ios_sock;
	asp->as_wrkrsd = imp->fd;
	asp->as_tls = iosp->ios_tls;
	asp->as_iop = iop;
	iop->io_ssntype = IO_AUTHSSN;
	iop->io_ssn = asp;
	strlcpy(asp->as_user, (char *)imp->data, MAXARGLEN + 1);
	RB_REMOVE(iotr, &iossnhead, iosp);
	free(iosp);
	if (RB_INSERT(authnmtr, &authssnhead, asp) != NULL)
		errx(1, "RB_INSERT on authnmtr");
	/* Setup authssn timeout */
	ssntimerreset(asp);
	
	/* setup io event for readtls */
	if (fcntl(asp->as_wrkrsd, F_SETFL, O_NONBLOCK) == -1) {
		killssncb(iop);
		return;
	}
	imsg_init(&asp->as_imb, asp->as_wrkrsd);
	asp->as_flags |= ASF_GOAHEAD;
	rv = imsg_compose(&asp->as_imb, WRKR_GOAHEAD, 0, 0, -1, &zero,
	    sizeof zero);
	if (rv == -1) {
		killssncb(iop);
		return;
	}
	event_set(&iop->io_ev, asp->as_wrkrsd, EV_WRITE, wrkrimsgwrite, iop);
	if (event_add(&iop->io_ev, NULL)) {
		killssncb(iop);
		return;
	}

	return;
}

static unsigned long
newpeerid(void) {
	static unsigned long rv = 0;

	return ++rv;
}

static void
clearima(struct io *iop) {
	struct iossn	*iosp;

	if (iop->io_ssntype != IO_IOSSN)
		errx(1, "clearima");
	iosp = iop->io_ssn;
	explicit_bzero(&iosp->ios_ima, sizeof iosp->ios_ima);
}
	
static void
ssntimerreset(struct authssn *asp) {
	struct io	*iop;

	iop = asp->as_iop;
	evtimer_del(&asp->as_timeev);
	asp->as_timeval.tv_sec = time(NULL);
	timeradd(&asp->as_timeval, &ssntimeout, &asp->as_timeval);
	evtimer_set(&asp->as_timeev, killssn, iop);
	evtimer_add(&asp->as_timeev, &asp->as_timeval);
}

static void
killssn(int fd, short event, void *arg) {
	struct io	*iop;

	iop = arg;
	killssncb(iop);
	return;
}

static void
killssncb(struct io *iop) {
	struct iossn	*iosp;
	struct authssn	*asp;

	if (event_del(&iop->io_ev))
		err(1, "event_del in killssncb");
	explicit_bzero(iop->io_buf, sizeof iop->io_buf);

	if (iop->io_ssntype == IO_AUTHSSN) {
		asp = iop->io_ssn;
		evtimer_del(&asp->as_timeev);
		RB_REMOVE(authnmtr, &authssnhead, asp);
		if (tls_close(asp->as_tls))
			errx(1, "tls_close");
		tls_free(asp->as_tls);
		if (close(asp->as_clntsd) || close(asp->as_wrkrsd))
			err(1, "killssncb close");
		msgbuf_clear(&asp->as_imb.w);
		free(asp);
	} else if (iop->io_ssntype == IO_IOSSN) {
		iosp = iop->io_ssn;
		evtimer_del(&iosp->ios_timeev);
		RB_REMOVE(iotr, &iossnhead, iosp);
		if (tls_close(iosp->ios_tls))
			errx(1, "tls_close");
		tls_free(iosp->ios_tls);
		if (close(iosp->ios_sock))
			err(1, "killssncb close");
		/* So paranoid... */
		explicit_bzero(&iosp->ios_ima, sizeof iosp->ios_ima);
		free(iosp);
	} else
		errx(1, "invalid ssntype");

	free(iop);
	return;
}
