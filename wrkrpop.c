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
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/limits.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "imsgpop.h"
#include "logutil.h"

#define MAXDELERESP	(25)
#define MAXSTATRESP	(29)
#define MMUIDLLEN	(65) /* sha256 hash len */
#define MAXRESPLEN	(IOBUFLEN - 5)
#define MAXTEMPLEN	(24)
#define MAXUIDLLEN	(80)
#define LLMLEN		(20) /* long long max digit length in base 10 */

size_t	totbytes,
	curbytes,
	totfiles,
	curfiles;

struct mailmsg {
	RB_ENTRY(mailmsg)	entry; /* for NOT deleted */
	RB_ENTRY(mailmsg)	dentry;  /* for deleted */
	size_t			mm_num;
	size_t			mm_bytes;
	uint8_t			mm_flags; /* see below */
	char			mm_uidl[MMUIDLLEN]; /* sha256 hash */
	char			mm_name[NAME_MAX+1]; /* filename - ish */
};

/* for mm_flags */
#define MM_SEEN		1

/* SLIST_HEAD(, mailmsg) mmlh; */

int
mmcmp(struct mailmsg *a, struct mailmsg *b) {
	if (a->mm_num < b->mm_num)
		return -1;
	return (a->mm_num > b->mm_num);
}

/* Deleted tree */
RB_HEAD(mdtr, mailmsg) mmdt = RB_INITIALIZER(&mmdt);
RB_PROTOTYPE(mdtr, mailmsg, dentry, mmcmp)
RB_GENERATE(mdtr, mailmsg, dentry, mmcmp)

/* Non-deleted tree */	
RB_HEAD(mmtr, mailmsg) mmhd = RB_INITIALIZER(&mmhd);
RB_PROTOTYPE(mmtr, mailmsg, entry, mmcmp)
RB_GENERATE(mmtr, mailmsg, entry, mmcmp)

struct imsgbuf	myimb;
struct event	myev;
int		mysock, shrinkpc = 0, receivedgoahead = 0;

static void sendresp(char *, void (*)(void));
static void recvcomm(void);

static void makedirs(void);
static void readpopcache(void);
static void freeents(struct dirent **, int);
static void freetree(void);
static void redopopcache(FILE *, struct dirent **, int);
static int mmsel(const struct dirent *);
static int mmcomp(const struct dirent **, const struct dirent **);

static void statcmd(void);
static void listcmd(size_t msg);
static void retrcmd(size_t msg);
static void delecmd(size_t msg);
static void noopcmd(void);
static void rsetcmd(void);
static void quitcmd(void);
static void updtwr(FILE *, char *, ssize_t, int, long *);
static void setseen(struct mailmsg *);
static void printpound(FILE *, long *, ssize_t);
static void imsgread(int, short, void *);
static void parse_command(ssize_t, char *);
static int getarg(size_t *, char *, ssize_t, int);

/* argv[] has the following: 0-progname, 1-username, 2-homedir,
 * 3-uidstr, 4-gidstr, 5-descriptor, 6-mymaildir, 7-debuglevel */
int
main(int argc, char *argv[]) {
	/* These will be read from the user file in the future. */
	size_t	sz;
	uid_t	myuid = 1000, tmpu; /* From argv[4] */
	gid_t	mygid = 1000, tmpg; /* From argv[5] */
	char	chrootdir[PATH_MAX], logid[8+40+1] = "wrkrpop ";

	debuglevel = strtonum(argv[7], 0, 50, NULL);
	if (debuglevel >= 10)
		sleep(60);
	closelog(); /* Prob not necessary */
	strlcat(logid, argv[1], sizeof logid);
	log_init(logid);
	dlog(1, "entering main, debuglevel %d", debuglevel);
	/* setproctitle("%s", logid); */
	mysock = strtonum(argv[5], 3, INT_MAX, NULL);
	if (mysock == 0)
		lerr(1, "strtonum");
	if (dup2(mysock, 3) == -1)
		lerr(1, "dup2");

	mysock = 3;
	closefrom(4);
	if (fcntl(3, F_SETFL, O_NONBLOCK) == -1)
		lerr(1, "fcntl");

	/* Maybe have to add a /Maildir to argv[3] */
	sz = strlcpy(chrootdir, argv[2], sizeof chrootdir);
	if (sz >= sizeof chrootdir)
		lerrx(1, "strlcpy chrootdir");
	sz = strlcat(chrootdir, argv[6], sizeof chrootdir);
	if (sz >= sizeof chrootdir)
		lerrx(1, "strlcat chrootdir");
	if (unveil(chrootdir, "rwc") || chdir(chrootdir))
		lerr(1, "chroot/chdir");

	if ((tmpu = strtonum(argv[3], 1, UID_MAX, NULL)))
		myuid = tmpu;
	if ((tmpg = strtonum(argv[4], 1, GID_MAX, NULL)))
		mygid = tmpg;
	
	if (setgroups(1, &mygid) || setresgid(mygid, mygid, mygid) ||
	    setresuid(myuid, myuid, myuid))
		lerr(1, "set{groups,res{g,u}id}");

	makedirs();

	/* I guess pledge anything additional here that we would like? */
	imsg_init(&myimb, mysock);

	event_init();
	event_set(&myev, mysock, EV_READ, imsgread, NULL);
	recvcomm(); /* Essentially just event_add */

	pledge("stdio rpath wpath cpath flock", NULL);
	event_dispatch();

	exit(1);
}

static void
makedirs(void) {
	char		*dirs[3] = {"tmp", "new", "cur"};
	struct stat	 sb;
	size_t		 i;

	for (i = 0; i < 3; ++i) {
		if (stat(dirs[i], &sb)) {
			if (errno == ENOENT) {
				if (mkdir(dirs[i], 0700))
					lerr(1, "mkdir");
			} else
				lerr(1, "stat");
		} else if (!S_ISDIR(sb.st_mode))
			lerrx(1, "not in a maildir");
	}
}

static void
freeents(struct dirent **epp, int ne) {
	int	i;

	for (i = 0; i < ne; ++i)
		free(epp[i]);
	free(epp);
}

static void
freetree(void) {
	struct mailmsg	*mmp, *mmtp;

	RB_FOREACH_SAFE(mmp, mmtr, &mmhd, mmtp) {
		RB_REMOVE(mmtr, &mmhd, mmp);
		free(mmp);
	}
}

static void
redopopcache(FILE *fp, struct dirent **epp, int ne) {
	EVP_MD_CTX	*emcp;
	struct mailmsg	*mmp;
	struct dirent	*entp;
	FILE		*mailfp;
	unsigned char	 uidlmd[EVP_MAX_MD_SIZE];
	char		 canonname[NAME_MAX+1], uidl[MMUIDLLEN], *cp, *lp;
	char		 openname[PATH_MAX], curname[] = "cur/";
	char		 bytesbuf[LLMLEN + 1];
	ssize_t		 len;
	size_t		 sz, bytes, cnlen, n;
	int		 i, j, bblen, mdlen;

	dlog(1, "entering redopopcache");
	fflush(fp);
	if (fseek(fp, 0, SEEK_SET))
		lerr(1, "fseek");
	/* We haven't written anything to the file so this shouldn't
	 * cause any problems with buffering. */
	ftruncate(fileno(fp), 0);
	/* Now we loop through each entp, get the canonname, write it,
	 * get the size (double counting each '\n', and get the hash
	 * of the canonname. We also build the mmtree. */
	totfiles = curfiles = ne; /* We already know this, so do it */
	totbytes = 0;
	emcp = EVP_MD_CTX_new();
	for (i = 0; i < ne; ++i) {
		/* Setup */
		bytes = 0;
		entp = epp[i];
		if ((mmp = calloc(1, sizeof *mmp)) == NULL)
			lerr(1, "calloc");
		mmp->mm_num = i + 1;
		/* Get file name for openname and mm_name. */
		strlcpy(openname, curname, sizeof openname);
		sz = strlcat(openname, entp->d_name, sizeof openname);
		if (sz >= sizeof openname)
			lerrx(1, "strlcat openname");
		sz = strlcpy(mmp->mm_name, entp->d_name, sizeof mmp->mm_name);
		if (sz >= sizeof mmp->mm_name)
			lerrx(1, "strlcpy mm_name");
		/* Get canonname */
		sz = strlcpy(canonname, entp->d_name, sizeof canonname);
		if (sz >= sizeof canonname)
			lerrx(1, "strlcpy canonname");
		if ((cp = strchr(canonname, ':')) != NULL)
			*cp = '\0';
		cnlen = strlen(canonname);
		/* Write filename plus " " */
		if (fwrite(canonname, cnlen, 1, fp) != 1)
			lerr(1, "fwrite canonname");
		if (fwrite(" ", 1, 1, fp) != 1)
			lerr(1, "fwrite space");
		/* Get bytes */
		if ((mailfp = fopen(openname, "r")) == NULL)
			lerr(1, "fopen");
		lp = NULL;
		n = 0;
		/* Is this a wildly inefficient way to count this? */
		while ((len = getline(&lp, &n, mailfp)) != -1)
			bytes += len + 1;
		free(lp);
		if (ferror(mailfp))
			lerr(1, "getline");
		if (fclose(mailfp) == EOF)
			lerr(1, "fclose");
		/* Record bytes */
		totbytes += bytes;
		mmp->mm_bytes = bytes;
		/* Write bytes plus " " */
		bblen = snprintf(bytesbuf, sizeof bytesbuf, "%zu ", bytes);
		if (bblen < 0 || bblen >= sizeof bytesbuf)
			lerrx(1, "snprintf");
		if (fwrite(bytesbuf, bblen, 1, fp) != 1)
			lerr(1, "fwrite");
		/* Get uidl from hash of canonname */
		EVP_DigestInit_ex(emcp, EVP_sha256(), NULL);
		EVP_DigestUpdate(emcp, canonname, cnlen);
		EVP_DigestFinal_ex(emcp, uidlmd, &mdlen);
		if (mdlen != 32)
			lerrx(1, "EVP_DigestFinal_ex");
		for (j = 0; j < mdlen; ++j) {
			if (snprintf(&uidl[2*j], 3, "%02x", uidlmd[j]) != 2)
				lerrx(1, "snprintf uidl");
		}
		if (strnlen(uidl, sizeof uidl) != 64)
			lerrx(1, "strnlen uidl");
		/* Write uidl and '\n' */
		if (fwrite(uidl, 64, 1, fp) != 1 ||
		    fwrite("\n", 1, 1, fp) != 1)
			lerr(1, "fwrite");
		if (strlcpy(mmp->mm_uidl, uidl, 65) != 64)
			lerrx(1, "strlcpy uidl");
		/* Epilogue */
		if (RB_INSERT(mmtr, &mmhd, mmp) != NULL)
			lerrx(1, "duplicate RB_INSERT");
		EVP_MD_CTX_reset(emcp);
	}
	fflush(fp);
	EVP_MD_CTX_free(emcp);
}

static int
mmsel(const struct dirent *entp) {
	char	*cp;
	size_t	 n = 0;
	
	if (entp->d_type == DT_REG) {
		cp = strchr(entp->d_name, '.');
		if (cp == NULL)
			return 0;
		
		while (isdigit(entp->d_name[n]))
			++n;
		if (n != 0 && cp == &entp->d_name[n])
			return 1;
	}
	return 0;
}

static int
mmcomp(const struct dirent **app, const struct dirent **bpp) {
	const struct dirent	*ap, *bp;
	char			*cp, anums[NAME_MAX+1], bnums[NAME_MAX+1];
	size_t			 anum, bnum, sz;

	ap = *app;
	if ((sz = strlcpy(anums, ap->d_name, NAME_MAX+1)) >= NAME_MAX+1)
		lerrx(1, "name_max");
	cp = strchr(anums, '.');
	if (cp != NULL)
		*cp = '\0';
	bp = *bpp;
	if ((sz = strlcpy(bnums, bp->d_name, NAME_MAX+1)) >= NAME_MAX+1)
		lerrx(1, "name_max");
	cp = strchr(bnums, '.');
	if (cp != NULL)
		*cp = '\0';

	anum = strtonum(anums, 1, LLONG_MAX, NULL);
	bnum = strtonum(bnums, 1, LLONG_MAX, NULL);
	/* This should only happen if we have too big a number */
	if (anum == 0 || bnum == 0)
		lerrx(1, "bad mailmsg");

	if (anum < bnum)
		return -1;
	if (anum > bnum)
		return 1;

	if (strcmp(ap->d_name, bp->d_name) == 0)
		return 0;

	anums[strlen(anums)] = '.';
	bnums[strlen(bnums)] = '.';
	return alphasort(app, bpp); /* lexicographic sort otherwise */
}

/* Check if the file popcache exists (done). Open it if so, create it
 * if not (done). Then get an exclusive lock on it (done). Then loop
 * through the files in the "new" directory, moving them to the cur
 * one. Put them in a tree structure sorted by date (aka
 * alphabetical). Check to see if each one has an entry in the
 * popcache. If so, use it to get pop-compliant byte counts and other
 * info. Otherwise compute the byte counts ourselves. */
static void
readpopcache(void) {
	struct mailmsg	*mmp;
	struct stat	 pcsb;
	struct dirent	*entp, **epp;
	FILE		*fp;
	DIR		*dp;
	ssize_t		 len;
	size_t		 n, szn, szc, szu, skipped;
	size_t		 somn = NAME_MAX+1, somu = MMUIDLLEN;
	int		 fd, numents, ent, haserrs = 0;
	char		*lp, *tp, *cp, newsrc[PATH_MAX], curdst[PATH_MAX];

	dlog(1, "entering readpopcache");
	/* Upon further review, this if/else block really just makes
	 * sure that popcache is a regular file. */
	if (stat("popcache", &pcsb)) {
		if (errno != ENOENT)
			lerr(1, "stat popcache");
	} else {
		if (!S_ISREG(pcsb.st_mode))
			lerrx(1, "popcache not reg");
	}
	/* Open popcache (creating if necc) and get a lock on it) */
	if ((fd = open("popcache", O_RDWR | O_CREAT | O_EXLOCK, 0640)) == -1)
		lerr(1, "popcache open");
	/* Move all messages from new to cur */
	if ((dp = opendir("new")) == NULL)
		lerr(1, "opendir new");
	for (entp = readdir(dp); entp != NULL; entp = readdir(dp)) {
		if (entp->d_type == DT_REG && entp->d_name[0] != '.') {
			strcpy(newsrc, "new/");
			strcpy(curdst, "cur/");
			szn = strlcat(newsrc, entp->d_name, PATH_MAX);
			szu = strlcat(curdst, entp->d_name, PATH_MAX);
			if (szn >= PATH_MAX || szu >= PATH_MAX)
				lerrx(1, "strlcat");
			if (rename(newsrc, curdst))
				lerr(1, "rename");
		}
	}
	if (closedir(dp))
		lerr(1, "closedir");
	/* What next? We need to create the mailmsgtree (mmtree)
	 * from popcache.*/
	if ((numents = scandir("cur", &epp, mmsel, mmcomp)) == -1)
		lerr(1, "scandir");
	if ((fp = fdopen(fd, "r+")) == NULL)
		lerr(1, "fdopen");
	lp = NULL;
	n = ent = 0;
	totbytes = totfiles = skipped = 0;
	/* So I'm going to assume that the list is in order when we do
	 * sanity checking. We already assumed that mm_file would be
	 * the actual file name when we were done. */
	/* Format for file is "canonfilename SP bytes SP uidl LF" */
	while ((len = getline(&lp, &n, fp)) != -1) {
		if (*lp == '#') {
			++skipped;
			continue;
		}
		if ((mmp = calloc(1, sizeof *mmp)) == NULL)
			/* Consider this a real error b/c if we can't
			 * alloc enough memory for the mailmsg's we're
			 * screwed */
			lerr(1, "calloc");
		mmp->mm_num = ++totfiles;
		if (ent >= numents) /* More entries in popcache than files */
			goto err;
		entp = epp[ent++];
		
		/* Get mm_name */
		cp = lp;
		if ((tp = strchr(cp, ' ')) == NULL)
			goto err;
		*tp++ = '\0'; /* tp now at bytes field */
		szn = strlcpy(mmp->mm_name, entp->d_name, somn);
		if (szn >= somn)
			goto err;
		if (strstr(mmp->mm_name, cp) != mmp->mm_name)
			goto err;
		if ((szc = strlen(cp)) != szn && mmp->mm_name[szc] != ':')
			goto err;
		
		/* Get mm_bytes */
		cp = tp; /* cp at bytes field */
		if ((tp = strchr(cp, ' ')) == NULL)
			goto err;
		*tp++ = '\0'; /* tp now at uidl field */
		mmp->mm_bytes = strtonum(cp, 1, LLONG_MAX, NULL);
		if (mmp->mm_bytes == 0)
			goto err;
		totbytes += mmp->mm_bytes;
		
		/* Get mm_uidl */
		cp = tp; /* cp at uidl field */
		if ((tp = strchr(cp, '\n')) == NULL)
			goto err;
		*tp = '\0';
		szu = strlcpy(mmp->mm_uidl, cp, somu);
		if (szu >= somu)
			goto err;

		/* Add to the tree */
		if (RB_INSERT(mmtr, &mmhd, mmp) != NULL)
			lerrx(1, "RB_INSERT");

		continue;
	err:
		haserrs = 1;
		free(mmp);
		break;
	}
	free(lp);
	if (ferror(fp))
		lerr(1, "ferror");
	/* Make sure not more entries in dir than in popfile */
	if (haserrs || totfiles != numents)
		goto redo;
	/* If we made it this far, we're good, but we don't need to
	 * condense popcache if we redo it. */
	if (skipped > numents/2)
		/* We use this to condense popcache on quit */
		shrinkpc = 1;
	goto done;
redo:
	/* This is where we redo the popcache file */
	freetree();
	redopopcache(fp, epp, numents);
done:
	freeents(epp, numents);
	if (fclose(fp) == EOF)
		lerr(1, "fclose");
	curfiles = totfiles;
	curbytes = totbytes;
	
	return;
}

static void
statcmd(void) {
	/* '+OK '(4) + 10 + 1 + 10 + 1 = 26, 10 is max decimal output
	 * of size_t when size_t is 8 bytes. If you have more than
	 * 2^64 bytes in your mailbox, that's a problem anyway. */
	char	response[MAXSTATRESP];
	size_t	rv;

	dlog(1, "entering statcmd");
	/* sendresp() in authpop adds the /r/n */
	rv = snprintf(response, MAXSTATRESP, "+OK %zu %zu\r\n", curfiles,
	    curbytes);
	if (rv < 0 || rv >= MAXSTATRESP)
		lerrx(1, "statcmd");
	sendresp(response, recvcomm);
	return;
}

static void
listcmd(size_t msgnum) {
	/* 24 = 2*10 + sp + crlf + NUL */
	struct mailmsg	*mmp, mymm;
	int		 rv;
	char		*cp, response[MAXRESPLEN], temp[MAXTEMPLEN];
	size_t		 sz, sor = sizeof response, sot = sizeof temp;

	dlog(1, "entering listcmd %zu", msgnum);
	if (msgnum) {
		mymm.mm_num = msgnum;
		if ((mmp = RB_FIND(mmtr, &mmhd, &mymm)) == NULL) {
			rv = sprintf(response, "-ERR no such msg\r\n");
			if (rv < 0)
				lerr(1, "listcmd sprintf");
			sendresp(response, recvcomm);
			return;
		}
		if (msgnum != mmp->mm_num) /* paranoid... */
			lerr(1, "fatal listcmd");
		rv = snprintf(response, sor, "+OK %zu %zu\r\n",
		    msgnum, mmp->mm_bytes);
		if (rv < 0 || rv >= sor) /* also paranoid... */
			lerr(1, "listcmd snprintf");
		sendresp(response, recvcomm);
		return;
	}
	/* We need to send all the scan listings */
	rv = sprintf(response, "+OK\r\n");
	if (rv < 0)
		lerr(1, "listcmd sprintf");
	cp = response + rv;
	RB_FOREACH(mmp, mmtr, &mmhd) {
		rv = snprintf(temp, sot, "%zu %zu\r\n", mmp->mm_num,
		    mmp->mm_bytes);
		if (rv < 0 || rv >= sot)
			lerr(1, "listcmd snprintf");
		sz = strlcat(response, temp, sor);
		if (sz >= sor) {
			/* last crlf added in authpop - Not anymore */
			*cp = '\0';
			sendresp(response, NULL);
			sz = strlcpy(response, temp, sor);
			if (sz >= sor)
				lerr(1, "listcmd strlcpy");
		}
		cp = response + sz;
	}
	/* We have all the scan listings sent or in our
	 * response[].  Try to add the terminating line (last
	 * crlf is added in authpop - not anymore). */
	sz = strlcat(response, ".\r\n", sor);
	if (sz >= sor) {
		*cp = '\0';
		sendresp(response, NULL);
		/* This is unfortunately super inefficient,
		 * but what can you do...*/
		strcpy(response, ".\r\n");
	}
	sendresp(response, recvcomm);
	return;
}


static void
retrcmd(size_t num) {
	struct mailmsg	*mmp, mymm;
	FILE		*fp;
	char		*lp, *cp, openbuf[PATH_MAX] = "cur/";
	char		 response[MAXRESPLEN];
	size_t		 n, lpoff, sz, sor = sizeof response;
	ssize_t		 len, mylen;
	int		 rv, shouldbreak;

	dlog(1, "entering retrcmd %zu", num);
	mymm.mm_num = num;
	if ((mmp = RB_FIND(mmtr, &mmhd, &mymm)) == NULL) {
		rv = sprintf(response, "-ERR message not found\r\n");
		if (rv < 0)
			lerr(1, "retrcmd sprintf");
		sendresp(response, recvcomm);
		return;
	}

	if (strlcat(openbuf, mmp->mm_name, sizeof openbuf) >= sizeof openbuf)
		lerrx(1, "strlcat"); /* This really shouldn't happen */
	/* This will fail b/c we're not in cur (not anymore) */
	if ((fp = fopen(openbuf, "r")) == NULL)
		lerr(1, "fopen");
	if ((rv = sprintf(response, "+OK\r\n")) < 0)
		lerr(1, "retrcmd sprintf");
	cp = response + rv;
	lp = NULL;
	n = 0;
	while ((len = getline(&lp, &n, fp)) != -1) {
		/* First add the dot if necessary */
		if (*lp == '.') { /* We need to add the '.' */
			if (strlcat(response, ".", sor) >= sor) {
				*cp = '\0'; /* Paranoid */
				sendresp(response, NULL);
				strlcpy(response, ".", sor);
				cp = response + 1;
			} else /* Added cleanly. */
				++cp;
		}
		lp[len-1] = '\0'; /* We'll deal with eol ourselves */
		mylen = len - 1; /* len-1 b/c we'll add crlf at end */
		lpoff = 0; /* how far are we in the line? */
		shouldbreak = 0;
		while (!shouldbreak) {
			if ((sz = strlcat(response, &lp[lpoff], sor)) >= sor) {
				/* How much did we actually write? */
				lpoff += (&response[sor] - cp);
				sendresp(response, NULL);
				cp = response;
				*response = '\0'; /* for strlcat */
			} else { /* We wrote the rest of the line */
				shouldbreak = 1;
				cp = response + sz;
				if (strlcat(response, "\r\n", sor) >= sor) {
					*cp = '\0';
					sendresp(response, NULL);
					strlcpy(response, "\r\n", sor);
					cp = response + 2;
				} else /* Added cleanly */
					cp += 2;
			}
		}
		/* Make sure there's something in response before looping */
	}
	free(lp);
	if (ferror(fp))
		lerr(1, "ferror");

	/* We still have stuff in the response[]. See if we can add
	 * the terminal "." */
	if ((sz = strlcat(response, ".\r\n", sor)) >= sor) {
		/* Dang it */
		*cp = '\0';
		sendresp(response, NULL);
		strcpy(response, ".\r\n");
	}
	sendresp(response, recvcomm);
	if (fclose(fp) == EOF)
		lerr(1, "fclose");
	mmp->mm_flags |= MM_SEEN;
	return;
}

static void
delecmd(size_t num) {
	struct mailmsg	*mmp, mymm;
	char		 response[MAXDELERESP];
	size_t		 sor = sizeof response;

	dlog(1, "entering delecmd %zu", num);
	mymm.mm_num = num;
	if ((mmp = RB_FIND(mmtr, &mmhd, &mymm)) == NULL) {
		if (strlcpy(response, "-ERR no such message\r\n", sor) >= sor)
			lerrx(1, "strlcpy");
		sendresp(response, recvcomm);
		return;
	}
	RB_REMOVE(mmtr, &mmhd, mmp);
	--curfiles;
	curbytes -= mmp->mm_bytes;

	if (RB_INSERT(mdtr, &mmdt, mmp) != NULL)
		lerrx(1, "duplicate on RB_INSERT");

	if (strlcpy(response, "+OK deleted\r\n", sor) >= sor)
		lerrx(1, "strlcpy");
	sendresp(response, recvcomm);
	return;
}

static void
noopcmd(void) {
	char	response[] = "+OK\r\n";
	dlog(1, "entering noopcmd");
	sendresp(response, recvcomm);
	return;
}

static void
rsetcmd(void) {
	struct mailmsg	*mmp, *tmmp;
	char		 response[] = "+OK\r\n";

	/* while (!SLIST_EMPTY(&mmlh)) { */
	/* 	mmp = SLIST_FIRST(&mmlh); */
	/* 	SLIST_REMOVE_HEAD(&mmlh, next); */
	/* 	if (RB_INSERT(mmtr, &mmhd, mmp) != NULL) */
	/* 		lerrx(1, "RB_INSERT"); */
	/* } */
	dlog(1, "entering rsetcmd");
	RB_FOREACH_SAFE(mmp, mdtr, &mmdt, tmmp) {
		RB_REMOVE(mdtr, &mmdt, mmp);
		if (RB_INSERT(mmtr, &mmhd, mmp) != NULL)
			lerrx(1, "duplicate on RB_INSERT");
	}
	curfiles = totfiles;
	curbytes = totbytes;

	sendresp(response, recvcomm);
	return;
}

static void
uidlcmd(size_t msgnum) {
	struct mailmsg	*mmp, mymm;
	int		 rv;
	char		*cp, response[MAXRESPLEN], temp[MAXUIDLLEN];
	size_t		 sz, sor = sizeof response, sot = sizeof temp;

	dlog(1, "entering uidlcmd %zu", msgnum);
	if (msgnum) {
		mymm.mm_num = msgnum;
		if ((mmp = RB_FIND(mmtr, &mmhd, &mymm)) == NULL) {
			rv = sprintf(response, "-ERR no such msg\r\n");
			if (rv < 0)
				lerr(1, "sprintf");
			sendresp(response, recvcomm);
			return;
		}
		if (msgnum != mmp->mm_num) /* Paranoid */
			lerr(1, "fatal uidl");
		rv = snprintf(response, sor, "+OK %zu %s\r\n", msgnum,
		    mmp->mm_uidl);
		if (rv < 0 || rv >= sor) /* also paranoid */
			lerr(1, "uidl snprintf");
		sendresp(response, recvcomm);
		return;
	}
	/* Send all the UIDLs */
	rv = sprintf(response, "+OK\r\n");
	if (rv < 0)
		lerr(1, "uidl sprintf");
	cp = response + rv;
	RB_FOREACH(mmp, mmtr, &mmhd) {
		rv = snprintf(temp, sot, "%zu %s\r\n", mmp->mm_num,
		    mmp->mm_uidl);
		if (rv < 0 || rv >= sot)
			lerr(1, "uidl snprintf");
		sz = strlcat(response, temp, sor);
		if (sz >= sor) {
			*cp = '\0';
			sendresp(response, NULL);
			sz = strlcpy(response, temp, sor);
			if (sz >= sor)
				lerr(1, "uidl strlcpy");
		}
		cp = response + sz;
	}

	sz = strlcat(response, ".\r\n", sor);
	if (sz >= sor) {
		*cp = '\0';
		sendresp(response, NULL);
		strcpy(response, ".\r\n");
	}
	sendresp(response, recvcomm);
	return;
}

static void
quitcmd(void) {
	struct mailmsg	*mymmp, *svmmp, *dlmmp;
	FILE		*fp;
	char		*lp, *tp, unbuf[PATH_MAX], cname[NAME_MAX+1];
	char		 errmsg[] = "-ERR\r\n", allgood[] = "+OK bye\r\n";
	ssize_t		 len;
	long		 wpos, savepos;
	size_t		 n, sz;
	int		 fd, needwr = 0;

	dlog(1, "entering quitcmd");
	wpos = 0;
	if ((fd = open("popcache", O_RDWR | O_EXLOCK)) == -1)
		goto error;
	if ((fp = fdopen(fd, "r+")) == NULL)
		goto error;
	/* Okay, so we've got our read and write FILE * */
	svmmp = RB_MIN(mmtr, &mmhd);
	dlmmp = RB_MIN(mdtr, &mmdt);
	n = 0;
	lp = NULL;
	while ((len = getline(&lp, &n, fp)) != -1) {
		if (*lp == '#') {
			if (!shrinkpc)
				wpos += len;
			needwr = 1;
			continue;
		}
		if ((tp = strchr(lp, ' ')) == NULL)
			lerrx(1, "file format");
		*tp = '\0';
		sz = strlcpy(cname, lp, sizeof cname);
		*tp = ' ';
		/* Check if the line is about the svmmp */
		if (svmmp && strstr(svmmp->mm_name, cname) == svmmp->mm_name &&
		    ((strlen(svmmp->mm_name) == sz) ||
		    svmmp->mm_name[sz] == ':')) {
			mymmp = svmmp;
			svmmp = RB_NEXT(mmtr, &mmhd, svmmp);
			/* If the seen flag is set, change the name */
			if (mymmp->mm_flags & MM_SEEN)
				setseen(mymmp);
			updtwr(fp, lp, len, needwr, &wpos);
		} else if (dlmmp &&
		    strstr(dlmmp->mm_name, cname) == dlmmp->mm_name &&
		    ((strlen(dlmmp->mm_name) == sz) ||
		    dlmmp->mm_name[sz] == ':')) {
			needwr = 1;
			mymmp = dlmmp;
			dlmmp = RB_NEXT(mdtr, &mmdt, dlmmp);
			if (!shrinkpc) {
				/* does this update wpos? */
				printpound(fp, &wpos, len);
			}
			strlcpy(unbuf, "cur/", sizeof unbuf);
			if (strlcat(unbuf, mymmp->mm_name, sizeof unbuf) >=
			    sizeof unbuf)
				goto error;
			if (remove(unbuf))
				goto error;
		} else {
			/* We should get through both trees before
			 * getting to new files. */
			if (!(dlmmp == NULL && svmmp == NULL))
				goto error;
			if (!shrinkpc)
				break;
			if ((savepos = ftell(fp)) == -1)
				goto error;
			if (fseek(fp, wpos, SEEK_SET))
				goto error;
			if (fwrite(lp, len, 1, fp) != 1)
				goto error;
			wpos += len;
			if (fseek(fp, savepos, SEEK_SET))
				goto error;
		}
	}
	free(lp);
	if (ferror(fp))
		goto error;

	fflush(fp);
	if (shrinkpc)
		ftruncate(fd, wpos);

	if (imsg_compose(&myimb, WRKR_END, 0, 0, -1, allgood, sizeof allgood)
	    == -1)
		lerr(1, "imsg_compose");
	if (imsg_flush(&myimb))
		lerrx(1, "authpop died or error");
	dlog(2, "quitcmd exiting 0");
	exit(0);
error:
	if (imsg_compose(&myimb, WRKR_END, 0, 0, -1, errmsg, sizeof errmsg)
	    == -1)
		lerr(1, "imsg_compose");
	if (imsg_flush(&myimb))
		lerr(1, "imsg_flush");
	dlog(2, "quitcmd exiting 1");
	exit(1);
}

static void
updtwr(FILE *p, char *cp, ssize_t l, int needswr, long *wpos) {
	long	curpos;

	dlog(2, "entering updtwr");
	if (!shrinkpc || !needswr) {
		/* Update pointer for wfp */
		*wpos += l;
		return;
	}

	if ((curpos = ftell(p)) == -1)
		lerr(1, "ftell");
	if (*wpos >= curpos)
		lerrx(1, "wpos > old");
	if (fseek(p, *wpos, SEEK_SET))
		lerr(1, "fseek");
	if (fwrite(cp, l, 1, p) != 1)
		lerr(1, "fwrite");
	*wpos += l;
	if (fseek(p, curpos, SEEK_SET))
		lerr(1, "fseek");
}

/* This is best effort. If anything fails, just return. */
static void
setseen(struct mailmsg *mmp) {
	char	 oldf[PATH_MAX] = "cur/", newf[PATH_MAX];
	char	*cp;

	if (strlcat(oldf, mmp->mm_name, sizeof oldf) >= sizeof oldf)
		return;
	strlcpy(newf, oldf, sizeof newf);
	if ((cp = strchr(oldf, ':')) != NULL) { /* Already have flags */
		if (strchr(cp, 'S') != NULL) /* Already have S */
			return;
		else {
			if (strlcat(newf, "S", sizeof newf) >= sizeof newf)
				return;
		}
	} else { /* Don't already have flags, add them */
		if (strlcat(newf, ":2,S", sizeof newf) >= sizeof newf)
			return;
	}
	rename(oldf, newf);
	return;
}

static void
printpound(FILE *fp, long *wpos, ssize_t l) {
	long	curpos;

	if ((curpos = ftell(fp)) == -1)
		lerr(1, "ftell");
	if (fseek(fp, *wpos, SEEK_SET))
		lerr(1, "fseek");
	if (fwrite("#", 1, 1, fp) != 1)
		lerr(1, "fwrite");
	*wpos += l;
	if (fseek(fp, curpos, SEEK_SET))
		lerr(1, "fseek");
	return;
}

/* This is done with blocking IO b/c what else do we need to do? */
static void
sendresp(char *cp, void (*cb)(void)) {
	size_t		cplen;
	uint32_t	type;

	dlog(1, "entering sendresp with%s callback", cb ? "" : "out");
	cplen = strnlen(cp, MAXRESPLEN);
	if (cplen >= MAXRESPLEN)
		lerrx(1, "sendresp response too long");
	++cplen;

	if (cb == NULL)
		type = WRKR_DATA;
	else
		type = WRKR_DATA_END;
		
	if (imsg_compose(&myimb, type, 0, 0, -1, cp, cplen) == -1)
		lerr(1, "imsg_compose");

	if (imsg_flush(&myimb))
		lerrx(1, "authpop died or error");

	if (cb == NULL)
		return;
	/* cb(); */
}

static void
recvcomm(void) {
	dlog(1, "entering recvcomm (event_add)");
	if (event_add(&myev, NULL))
		lerr(1, "event_add");
	
	return;
}

/* We don't have to worry about getting more than one (non-pipelined)
 * command at a time because authpop won't send them to us (aka listen
 * for readevents on the socket) until we send it a WRKR_DATA_END
 * imsg type. */
static void
imsgread(int fd, short event, void *arg) {
	struct imsg	myimsg;
	ssize_t		n, datalen;

	dlog(1, "entering imsgread");
	/* Read in imsg's when the event says it's readable. Complete
	 * every task necessary for each message before moving on to
	 * the next. Because we are just handling responses from the
	 * client (or root), we add the event listener back when we're
	 * done. This means we don't have to worry about adding events
	 * at the end of the function calls. */
	if ((n = imsg_read(&myimb)) == -1) {
		if (errno != EAGAIN)
			lerr(1, "imsg_read");
		recvcomm();
		return;
	}
	if (n == 0) {
		/* Had something to read but read nothing == authpop
		 * closed the connection. */
		dlog(1, "exiting 2 (timeout?)");
		exit(2);
	}

	for (;;) {
		if ((n = imsg_get(&myimb, &myimsg)) == -1)
			lerr(1, "imsg_get");
		if (n == 0)
			break;

		/* datalen must include terminating NULL byte */
		datalen = myimsg.hdr.len - IMSG_HEADER_SIZE;
		switch (myimsg.hdr.type) {
			/* Maybe we should just check if there's a session
			 * before we send to root from authpop. */
		case WRKR_GOAHEAD:
			if (receivedgoahead)
				lerrx(1, "too many goaheads");
			receivedgoahead = 1;
			readpopcache();
			break;
		case WRKR_DATA:
			if (!receivedgoahead)
				lerrx(1, "data before goahead");
			parse_command(datalen, (char *)myimsg.data);
			break;
		default:
			lerrx(1, "bad imsg type");
			break;
		}
		imsg_free(&myimsg);
	}
	recvcomm();
}

static int
getarg(size_t *mnump, char *cp, ssize_t len, int required) {
	size_t	n, numlen;
	char	numcp[MAXARGLEN+1];

	if (len == 7 && !required) {
		*mnump = 0;
		return 0;
	}

	if (cp[4] != ' ')
		return -1;

	if (len == 8 && !required) {
		*mnump = 0;
		return 0;
	}

	n = 5;
	numlen = 0;
	while (isdigit(cp[n]) && numlen <= MAXARGLEN) {
		++n;
		++numlen;
	}

	if (n != len - 3 || numlen == 0)
		return -1;

	memcpy(numcp, &cp[5], numlen);
	numcp[numlen] = '\0';
	if ((*mnump = strtonum(numcp, 1, LLONG_MAX, NULL)) == 0)
		return -1;

	return 0;
}

static void
parse_command(ssize_t len, char *cp) {
	size_t	 msgnum;

	dlog(2, "entering parse_command");
	/* len must be at least 7 because all commands are 4 bytes
	 * followed by at least \r\n\0. Even if we do implement top in
	 * the future, this requires two args so would also need more
	 * than 7 bytes. */
	if (len < 7 || len > MAXINPUTLEN + 1) {
		sendresp("-ERR bad command length\r\n", recvcomm);
		return;
	}

	if (cp[len - 1] != '\0' ||
	    cp[len - 2] != '\n' ||
	    cp[len - 3] != '\r') {
		sendresp("-ERR expected crlf to end\r\n", recvcomm);
		return;
	}

	if (strncasecmp("stat", cp, 4) == 0) {
		if (len != 7) {
			sendresp("-ERR bad stat command\r\n", recvcomm);
			return;
		}
		statcmd();
		return;
	} else if (strncasecmp("list", cp, 4) == 0) {
		if (getarg(&msgnum, cp, len, 0)) {
			sendresp("-ERR syntax\r\n", recvcomm);
			return;
		}
		listcmd(msgnum);
		return;
	} else if (strncasecmp("retr", cp, 4) == 0) {
		if (getarg(&msgnum, cp, len, 1) == -1) {
			sendresp("-ERR syntax\r\n", recvcomm);
			return;
		}
		retrcmd(msgnum);
		return;
	} else if (strncasecmp("dele", cp, 4) == 0) {
		if (getarg(&msgnum, cp, len, 1) == -1) {
			sendresp("-ERR syntax\r\n", recvcomm);
			return;
		}
		delecmd(msgnum);
		return;
	} else if (strncasecmp("noop", cp, 4) == 0) {
		if (len != 7) {
			sendresp("-ERR bad noop\r\n", recvcomm);
			return;
		}
		noopcmd();
		return;
	} else if (strncasecmp("rset", cp, 4) == 0) {
		if (len != 7) {
			sendresp("-ERR bad rset\r\n", recvcomm);
			return;
		}
		rsetcmd();
		return;
	} else if (strncasecmp("uidl", cp, 4) == 0) {
		if (getarg(&msgnum, cp, len, 0) == -1) {
			sendresp("-ERR syntax\r\n", recvcomm);
			return;
		}
		uidlcmd(msgnum);
		return;
	} else if (strncasecmp("quit", cp, 4) == 0) {
		if (len != 7) {
			sendresp("-ERR bad quit\r\n", recvcomm);
			return;
		}
		quitcmd();
		return;
	} else {
		sendresp("-ERR unrecognized command\r\n", recvcomm);
		return;
	}
}
