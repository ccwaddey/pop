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

#include <sys/stat.h>
/* #include <sys/types.h> */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void makedirs(FILE *);
/* This is the mda that we'll use for popcache. Our message is
 * delivered on standard input. We need to do the following: 1-Acquire
 * a lock on popcache, creating if needed. 2-Create the file name that
 * we're going to use. 3-Try to open the file in create mode with it
 * failing if the file already exists. Loop until a random file name
 * works. 4-Count the vbytes as we write to the tmpfile. 5- */
int
main(int argc, char *argv[]) {
	EVP_MD_CTX	*emcp;
	FILE		*infp, *pcfp, *tmpfp, *newfp;
	int		 pcfd, i, mdlen;
	char		 filename[NAME_MAX+1], hostname[HOST_NAME_MAX+1];
	char		 tmpname[NAME_MAX+5], newname[NAME_MAX+5], *lp;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	time_t		 now;
	uint32_t	 midrand;
	size_t		 rv, fnsz, n, bytes = 0;
	ssize_t		 len;

	infp = fopen("/home/me/pop/mdainfo", "a");
	if (chdir(argv[2])) {
		fprintf(infp, "could not chdir: %s\n", argv[2]);
		exit(1);
	}
	pcfd = open("popcache", O_WRONLY | O_APPEND | O_CREAT | O_EXLOCK,
	    0600);
	if (pcfd == -1) {
		fprintf(infp, "could not open popcache\n");
		exit(1);
	}
	pcfp = fdopen(pcfd, "a");
	if (gethostname(hostname, sizeof hostname))
		strlcpy(hostname, "localhost", sizeof hostname);
	/* Make dirs if needed */
	makedirs(infp);
	/* Get an unused file name in tmp, make sure it's not in new either. */
	for (;;) {
		now = time(NULL);
		midrand = arc4random();

		rv = snprintf(filename, sizeof filename, "%llu.%08x.%s",
		    (unsigned long long)now, midrand, hostname);
		if (rv < 0 || rv >= sizeof filename) {
			fprintf(infp, "filename too long: %llu.%08x.%s\n",
			    (unsigned long long)now, midrand, hostname);
			exit(1);
		}
		fprintf(infp, "filename: %s\n", filename);
		fnsz = rv;
		strlcpy(tmpname, "tmp/", sizeof tmpname);
		rv = strlcat(tmpname, filename, sizeof tmpname);
		if (rv >= sizeof tmpname) {
			fprintf(infp, "tmpname: %s\n", tmpname);
			exit(1);
		}
		if ((tmpfp = fopen(tmpname, "ax")) != NULL) {
			/* This really shouldn't overrun if tmp didn't */
			strlcpy(newname, "new/", sizeof newname);
			strlcat(newname, filename, sizeof newname);
			if ((newfp = fopen(newname, "ax")) != NULL) {
				fclose(newfp);
				break;
			}
			/* If we get here, tmp didn't exist, but new did */
			fclose(tmpfp);
			remove(tmpname);
		}
	}
	/* We have a good name */
	n = 0;
	lp = NULL;
	while ((len = getline(&lp, &n, stdin)) != -1) {
		fwrite(lp, len, 1, tmpfp);
		bytes += len + 1;
	}
	free(lp);
	if (ferror(stdin))
		exit(1);
	fflush(tmpfp);
	fclose(tmpfp);
	rename(tmpname, newname);
	/* Okay, so we've delivered the mail. Now get the info into popcache */
	emcp = EVP_MD_CTX_new();
	EVP_DigestInit_ex(emcp, EVP_sha256(), NULL);
	EVP_DigestUpdate(emcp, filename, fnsz);
	EVP_DigestFinal_ex(emcp, md, &mdlen);
	if (mdlen != 32)
		exit(1);/* Not really */
	fprintf(pcfp, "%s %zu ", filename, bytes);
	for (i = 0; i < 32; ++i) {
		fprintf(pcfp, "%02x", md[i]);
	}
	fprintf(pcfp, "\n");
	fflush(pcfp);
	exit(0);
}

static void
makedirs(FILE *p) {
	char		*dirs[3] = {"tmp", "new", "cur"};
	struct stat	 sb;
	int		 e = -1;
	size_t		 i;

	for (i = 0; i < 3; ++i) {
		if (stat(dirs[i], &sb)) {
			if (errno == ENOENT) {
				if (mkdir(dirs[i], 0700)) {
					e = 1;
					goto err;
				}
			} else {
				e = 2;
				goto err;
			}
		} else if (!S_ISDIR(sb.st_mode)) {
			e = 3;
			goto err;
		}
	}

	return;
err:
	fprintf(p, "%d: could not create dirs or not a maildir\n", e);
	exit(1);
}
