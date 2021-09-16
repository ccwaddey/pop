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

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

size_t tread(struct tls *, void *, size_t);
void twrite(struct tls *, void *, size_t);

int
main(int argc, char *argv[]) {
	char	buf[2048], *lp;
	/* int	sd; */
	size_t	n, nn;
	ssize_t	len;

	/* struct sockaddr_in	 maddr; */
	struct tls_config	*tlscfg;
	struct tls		*tlsp;

	/* maddr.sin_family = AF_INET; */
	/* maddr.sin_port = htons(995); */
	/* inet_pton(AF_INET, "192.168.0.9", &maddr.sin_addr); */

	tlscfg = tls_config_new();
	tls_config_set_protocols(tlscfg, TLS_PROTOCOL_TLSv1_3);
	tls_config_set_ca_file(tlscfg, "/etc/ssl/turtle.bsdopener.domain.crt");
	tlsp = tls_client();
	tls_configure(tlsp, tlscfg);

	/* sd = socket(AF_INET, SOCK_STREAM, 0); */

	/* if (connect(sd, (struct sockaddr *)&maddr, sizeof maddr)) */
	/* 	err(1, "connect"); */

	tls_connect(tlsp, "turtle.bsdopener.domain", "995");

	n = tread(tlsp, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	n = strlcpy(buf, "user user0000\r\n", sizeof buf);
	twrite(tlsp, buf, n);
	printf("%s", buf);

	n = tread(tlsp, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	n = strlcpy(buf, "pass password\r\n", sizeof buf);
	twrite(tlsp, buf, n);
	printf("%s", buf);

	n = tread(tlsp, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);
	fflush(stdout);

	lp = NULL;
	nn = 0;
	for (;;) {
		len = getline(&lp, &nn, stdin);
		if (len == -1)
			break;
		if (strncmp(lp, "rr\n", 3) == 0) {
			n = 0;
			puts("continued");
		} else {
			n = strlcpy(buf, lp, sizeof buf);
			twrite(tlsp, buf, n);
		}

		n = tread(tlsp, buf, 2048);
		buf[n] = '\0';
		printf("%s", buf);
		fflush(stdout);
	}
	exit(0);
}

size_t
tread(struct tls *t, void *b, size_t n) {
	ssize_t	rv;

	for (;;) {
		rv = tls_read(t, b, n);
		if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
			continue;
		if (rv == -1)
			exit(1);
		if (rv)
			return rv;
	}
}

void
twrite(struct tls *t, void *b, size_t n) {
	ssize_t rv;

	while (n > 0) {
		rv = tls_write(t, b, n);

		if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
			continue;
		if (rv == -1)
			exit(1);
		b += rv;
		n -= rv;
	}
}
