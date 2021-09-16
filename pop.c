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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "imsgpop.h"
#include "logutil.h"

/* #define MAXHASHLEN	65 */
/* The following will be turned into options for customization */
#define USERTAB		"/home/me/pop/testuser"
#define AUTHTAB		"/home/me/pop/testauth"
#define LSNRADDR	"192.168.0.9"
#define AUTHPOPFILE	"/home/me/pop/authpop"
#define WRKRPOPFILE	"/home/me/pop/wrkrpop"

char	*mymaildir = "";
char	*certfile = "/etc/ssl/turtle.bsdopener.domain.crt";
char	*keyfile = "/etc/ssl/private/turtle.bsdopener.domain.key";

enum {NOCHILD, YESCHILD};

int		lsnrsd;
pid_t		authpid;
struct event	lsnrev;
struct event	authev;		/* for reading */
struct event	authwev;	/* for writing */
struct imsgbuf	authimsgbuf;

struct usernode {
	char	*un_user;
	char	*un_hash;
	char	*un_home;
	char	*un_uid;
	char	*un_gid;
	RB_ENTRY(usernode) entry;
};

static void acceptconn(int, short, void *);
static void authread(int, short, void *);
static void authwrite(int, short, void *);
static void checkuserpass(struct imsgauth *imap, uint32_t);
static void childhandler(int);
static void loadusers(void);
static void sendsock(char *, uint32_t, int, int);
static int usercmp(struct usernode *, struct usernode *);

RB_HEAD(uncmp, usernode) uth = RB_INITIALIZER(&uth); /* usertreehead */
RB_PROTOTYPE_STATIC(uncmp, usernode, entry, usercmp)
RB_GENERATE_STATIC(uncmp, usernode, entry, usercmp)

int
main(int argc, char *argv[]) {
	int			set;
	socklen_t		setl;
	int			spv[2];
	struct sockaddr_in	lsnraddr;
	struct sigaction	childsa;

	log_init("popd");

	dlog(1, "entering main");
	loadusers();
	
	/* This sig handling stuff gets removed on execs, because it
	 * isn't ignored */
	childsa.sa_handler = childhandler;
	sigemptyset(&childsa.sa_mask);
	childsa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	if (sigaction(SIGCHLD, &childsa, NULL))
		lerr(1, "sigaction");

	event_init();
	
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, spv))
		lerr(1, "socketpair");
	if ((authpid = fork()) == -1)
		lerr(1, "fork");
	if (authpid == 0) {
		if (close(spv[1]))
			_exit(1);
		if (dup2(spv[0], 3) == -1) /* nonblock set in authpop (done) */
			_exit(1);

		/* maybe more args */
		dlog(1, "execing authpop");
		execl(AUTHPOPFILE, "authpop", certfile, keyfile,
		    NULL);
		_exit(1);
	} 

	if (close(spv[0]))
		lerr(1, "close");
	if (fcntl(spv[1], F_SETFL, O_NONBLOCK) == -1)
		lerr(1, "fcntl");
	imsg_init(&authimsgbuf, spv[1]);
	event_set(&authwev, authimsgbuf.fd, EV_WRITE, authwrite, NULL);
	event_set(&authev, authimsgbuf.fd, EV_READ | EV_PERSIST,
	    authread, NULL);
	if (event_add(&authev, NULL))
		lerr(1, "event_add");

	if ((lsnrsd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		lerr(1, "socket");

	set = 1;
	setl = sizeof set;
	if (setsockopt(lsnrsd, SOL_SOCKET, SO_REUSEADDR, &set, setl))
		lerr(1, "setsockopt");
	if (fcntl(lsnrsd, F_SETFL, O_NONBLOCK) == -1)
		lerr(1, "nonblocking");

	lsnraddr.sin_family = AF_INET;
	lsnraddr.sin_port = htons(995);
	if (inet_pton(AF_INET, LSNRADDR, &lsnraddr.sin_addr) != 1)
		lerr(1, "inet_pton");

	if (bind(lsnrsd, (struct sockaddr *)&lsnraddr, sizeof lsnraddr))
		lerr(1, "bind");
	if (listen(lsnrsd, 128)) /* 128 = default max; really shouldn't err */
		lerr(1, "listen");

	event_set(&lsnrev, lsnrsd, EV_READ | EV_PERSIST, acceptconn, NULL);
	if (event_add(&lsnrev, NULL))
		lerr(1, "event_add");

	/* pledge something here, as well as exec pledge for wrkr */
	dlog(1, "event_dispatch");
	event_dispatch();
}

/* Our general strategy for event structs in this program is to
 * statically allocate them (because we only care about 2 fds), and
 * for the one that isn't persistent (authwev) we check if it has
 * already been added (added with event_add) by calling event_pending
 * when we need to write something to it and then check if we're done
 * writing in the callback (authwrite) */
static void
acceptconn(int fd, short event, void *arg) {
	/* struct event	*evp; don't need */
	int	newsock, rv;
	dlog(1, "entering acceptconn");
accept:
	if ((newsock = accept(fd, NULL, NULL)) == -1) {
		if (errno == EWOULDBLOCK ||
		    errno == ECONNABORTED ||
		    errno == ENFILE ||
		    errno == EMFILE)
			return; /* temp problem or connaborted */
		else if (errno == EINTR)
			goto accept; /* try again */
		else
			lerr(1, "accept"); /* shouldn't happen */
	}

	rv = imsg_compose(&authimsgbuf, APRT_NEW_CONN, 0, 0, newsock,
	    &newsock, sizeof newsock);
	if (rv == -1)
		lerr(1, "imsg_compose acceptconn");

	dlog(2, "acceptconn adding authwev if not pending");
	if (!event_pending(&authwev, EV_WRITE, NULL))
		if (event_add(&authwev, NULL))
			lerr(1, "event_add authwev");
	
	return;
}

static void
authread(int fd, short event, void *arg) {
	struct imsg	 rdmsg;
	ssize_t		 n, datalen;
	
	dlog(1, "entering authread");
	if ((n = imsg_read(&authimsgbuf)) == -1) {
		if (errno == EAGAIN) /* authev is EV_PERSIST */
			return;
		lerr(1, "imsg_read");
	}
	if (n == 0)
		/* Didn't read anything but had stuff to read ==
		 * authpop died */
		lerrx(2, "authread read 0");

	for (;;) {
		if ((n = imsg_get(&authimsgbuf, &rdmsg)) == -1)
			/* Again, only legit fails b/c of malloc. */
			lerr(1, "imsg_get");
		if (n == 0)
			/* return is okay here instead of break b/c
			 * the event persists. */
			return;
		datalen = rdmsg.hdr.len - IMSG_HEADER_SIZE;
		
		switch(rdmsg.hdr.type) {
		case APRT_NEW_USER:
			/* This needs to be done with it's shit before
			 * returning */
			if (datalen != sizeof(struct imsgauth))
				lerrx(1, "authread: datalen error; peerid:"
				    " %u", rdmsg.hdr.peerid);
			checkuserpass((struct imsgauth *)rdmsg.data,
			    rdmsg.hdr.peerid);
			break;
		default:
			lerrx(1, "authread: bad imsg type");
			break;
		}
		imsg_free(&rdmsg); /* calls freezero */
	}
}

/* One might suspect that we have to worry about freeing the memory
 * used for sending which users we are talking about when we respond
 * to APRT_NEW_USER, but the memory that we send is copied and freed
 * by the imsg API, so we just need to free it after we add it to the
 * imsg queue. */
/* XXX I think this is done */
static void
authwrite(int fd, short event, void *arg) {
	int		 n;

	dlog(1, "entering authwrite");
	if (!authimsgbuf.w.queued)
		return;

	if ((n = msgbuf_write(&authimsgbuf.w)) == -1 && errno == EAGAIN)
		/* temporary resource shortage */
		goto add;

	if (n == -1)
		lerr(1, "authwrite: msgbuf_write");

	/* if we don't write anything and we had something to write
	 * and room to write it, it's an error, prob cause authpop
	 * died. */
	if (n == 0)
		lerrx(2, "authwrite: n == 0");

	/* if there are still imsgs, let us know when we can send
	 * them. */
	if (authimsgbuf.w.queued)
		goto add;
	return;
add:
	dlog(2, "authwrite: adding authwev");
	if (event_add(&authwev, NULL))
		lerr(1, "event_add");
}

/* This must do everything it needs to do except free the storage for
 * (char *)up or else shut down the program because this is the hook. */
static void
checkuserpass(struct imsgauth *imap, uint32_t peerid) {
	struct usernode	 untemp, *unp;
	int		 rv, srv, spv[2];
	pid_t		 wrkrpid;
	char		 descriptor[25]; /* Should always be enough space */

	dlog(1, "entering checkuserpass; peerid: %u, user: %s", peerid,
		imap->ima_userbuf);
	untemp.un_user = imap->ima_userbuf;
	if ((unp = RB_FIND(uncmp, &uth, &untemp)) == NULL || imap->ima_prefail) {
		dlog(2, "checkuserpass: peerid: %u, no user %s, prefail: %d",
		    peerid, untemp.un_user, imap->ima_prefail);
		sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
	}

	/* passwords should not be empty or else it's a security
	 * concern. */
	if (imap->ima_passbuf[0] == '\0') {
		dlog(2, "checkuserpass: peerid: %u, user: %s, empty password",
		    peerid, imap->ima_userbuf);
		sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
	}
	if ((rv = crypt_checkpass(imap->ima_passbuf, unp->un_hash)) == -1) {
		dlog(2, "checkuserpass: peerid: %u, bad password");
		sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
	} else { /* fork and send sock to auth */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, spv)) {
			dlog(2, "checkuserpass: socketpair fail");
			sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
			return;
		}
		srv = snprintf(descriptor, sizeof descriptor, "%d", spv[0]);
		if (srv <= 0 || srv >= sizeof descriptor) {
			dlog(2, "checkuserpass: snprintf descriptor fail");
			sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
			return;
		}
		if ((wrkrpid = fork()) == -1) {
			/* Fails only for memory and proc num limits */
			dlog(2, "checkuserpass: fork fail");
			sendsock(imap->ima_userbuf, peerid, -1, NOCHILD);
			return;
		}
		if (wrkrpid == 0) {
			/* Just need to make sure if wrkr fails that
			 * authpop handles it correctly */
			dlog(1, "checkuserpass: execing wrkrpop %s, %s, %s,"
			    " %s, %s, %s",
			    unp->un_user, unp->un_home, unp->un_uid,
			    unp->un_gid, descriptor, mymaildir);
			execl(WRKRPOPFILE, "wrkrpop",
			    unp->un_user, unp->un_home, unp->un_uid,
			    unp->un_gid, descriptor, mymaildir, NULL);
			/* Shouldn't get here */
			dlog(0, "checkuserpass: execl fail");
			_exit(1);
		} else if (wrkrpid > 0) { /* sendsock doesn't return for us */
			while (close(spv[0]))
				if (errno != EINTR)
					lerr(1, "close");
			dlog(1, "checkuserpass: success; peerid: %u, user: "
			    "%s, socket: %d", peerid, imap->ima_userbuf,
			    spv[1]);
			sendsock(imap->ima_userbuf, peerid, spv[1], NOCHILD);
		}
	}
}

/* We do need to lock both files for when we add a user. */
static void
loadusers(void) {
	FILE		*pfp, *ufp;
	int		 pfd, ufd;
	struct usernode	*unp, untemp;
	ssize_t		 len;
	size_t		 n;
	char		*lp, *tp, *cp, *newuser, *newhash, *newhome;
	char		*newuid, *newgid;

	dlog(1, "entering loadusers");
	/* Get shared locks on both files. If a program needs to
	 * modify either file, it needs to get exclusive locks in this
	 * order to avoid deadlocks. */
	if ((pfd = open(AUTHTAB, O_RDONLY | O_SHLOCK)) == -1)
		lerr(1, "open");
	if ((pfp = fdopen(pfd, "r")) == NULL)
		lerr(1, "fdopen");
	if ((ufd = open(USERTAB, O_RDONLY | O_SHLOCK)) == -1)
		lerr(1, "open");
	if ((ufp = fdopen(ufd, "r")) == NULL)
		lerr(1, "fdopen");

	n = 0;
	lp = NULL;
	while ((len = getline(&lp, &n, pfp)) != -1) {
		/* I'm pretty sure we shouldn't modify lp, so that
		 * free(lp) works. */
		tp = lp;
		/* parse each line for user name match; we only allow
		 * lowercase letters and digits (for now) */
		/* passfile format is "user" space(s) "hash" LF */
		while (islower(*tp) || isdigit(*tp))
			++tp;
		if (!isblank(*tp))
			lerrx(1, "passfile format");
		*tp++ = '\0';
		if ((newuser = strdup(lp)) == NULL)
			lerr(1, "newuser");
		while (isblank(*tp))
			++tp;
		*(lp + len - 1) = '\0';
		if ((newhash = strdup(tp)) == NULL)
			lerr(1, "newhash");
		if ((unp = calloc(1, sizeof *unp)) == NULL)
			lerr(1, "calloc unp");
		unp->un_user = newuser;
		unp->un_hash = newhash;
		if (RB_INSERT(uncmp, &uth, unp) != NULL)
			lerrx(1, "RB_INSERT");
	}
	free(lp);
	if (ferror(pfp))
		lerr(1, "getline");
	
	n = 0;
	lp = NULL;
	/* userfile format: "user" "spaces and/or tabs" uid:gid:home \n */
	while ((len = getline(&lp, &n, ufp)) != -1) {
		tp = lp;
		/* get user */
		while (islower(*tp) || isdigit(*tp))
			++tp;
		if (!isblank(*tp))
			lerrx(1, "usertab format");
		*tp++ = '\0';
		/* get uid */
		while (isblank(*tp))
			++tp;
		cp = tp; /* tp, cp now at uid */
		if ((tp = strchr(cp, ':')) == NULL)
			lerrx(1, "usertab format");
		*tp++ = '\0'; /* tp now at gid */
		if ((newuid = strdup(cp)) == NULL)
			lerrx(1, "strdup uid");
		/* get gid */
		cp = tp;
		if ((tp = strchr(cp, ':')) == NULL)
			lerrx(1, "usertab format");
		*tp++ = '\0';
		if ((newgid = strdup(cp)) == NULL)
			lerrx(1, "strtonum gid");
		/* get home */
		cp = tp;
		*(lp + len - 1) = '\0';
		if ((newhome = strdup(cp)) == NULL)
			lerr(1, "strdup newhome");
		/* get user */
		untemp.un_user = lp;
		if ((unp = RB_FIND(uncmp, &uth, &untemp)) == NULL)
			lerrx(1, "RB_FIND");
		if (unp->un_home != NULL)
			lerrx(1, "duplicate user entry");
		/* assign values */
		unp->un_uid = newuid;
		unp->un_gid = newgid;
		unp->un_home = newhome;
	}
	free(lp);
	if (ferror(ufp))
		lerr(1, "getline");

	if (flock(ufd, LOCK_UN))
		lerr(1, "flock");
	if (fclose(ufp) == EOF)
		lerr(1, "fclose");
	if (flock(pfd, LOCK_UN))
		lerr(1, "flock");
	if (fclose(pfp) == EOF)
		lerr(1, "fclose");
}

/* Only legit fails for no memory purposes, which shouldn't happen, so
 * okay to err. */
static void
sendsock(char *up, uint32_t peerid, int sock, int child) {
	dlog(1, "entering sendsock; sock: %d, peerid: %u, user: %s",
	    sock, peerid, up);
	if (!event_pending(&authwev, EV_WRITE, NULL))
		if (event_add(&authwev, NULL))
			child ? _exit(1) : lerr(1, "event_add");

	if (imsg_compose(&authimsgbuf, APRT_NEW_USER, peerid, 0, sock, up,
	    strlen(up) + 1) == -1)
		child ? _exit(1) : lerr(1, "imsg_compose");
}

/* This is done pretty sure */
static void
childhandler(int sig) {
	pid_t	chldpid;
	int	status;
	int	save_errno = errno;
	
	while (1) {
		chldpid = wait4(WAIT_ANY, &status, WNOHANG, NULL);
		if (chldpid == 0) /* finished */
			break;
		if (chldpid == authpid) /* authpop exited, so should we */
			exit(2);
		/* don't think should happen but not sure */
		if (chldpid == -1 && errno == ECHILD)
			break;
	}
	errno = save_errno;
	return;
}

/* Assumes a,b and their un_user fields are non-NULL */
static int
usercmp(struct usernode *a, struct usernode *b) {
	return strcmp(a->un_user, b->un_user);
}
