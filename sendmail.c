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
#include <unistd.h>

int
main(int argc, char *argv[]) {
	char	buf[1024], user[41] = "user0000", *lp;
	int	sd, usestdin = 0, nonl;
	ssize_t	len;
	size_t	n, gln;

	if (argc >= 2) {
		if (strcmp(argv[1], "-") == 0)
			usestdin = 1;
		else
			strlcpy(user, argv[1], sizeof user);
	}
	if (argc >= 3)
		usestdin = 1;

	struct sockaddr_in maddr;

	maddr.sin_family = AF_INET;
	maddr.sin_port = htons(925);
	inet_pton(AF_INET, "192.168.0.9", &maddr.sin_addr);

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(sd, (struct sockaddr *)&maddr, sizeof maddr))
		err(1, "connect");

	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);
	
	strcpy(buf, "ehlo turtle\r\n");
	write(sd, buf, strlen(buf));
	printf("%s", buf);
	
	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	strcpy(buf, "mail from:<user0000>\r\n");
	write(sd, buf, strlen(buf));
	printf("%s", buf);

	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	strcpy(buf, "rcpt to:<");
	strlcat(buf, user, sizeof buf);
	strlcat(buf, ">\r\n", sizeof buf);
	write(sd, buf, strlen(buf));
	printf("%s", buf);

	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	strcpy(buf, "data\r\n");
	write(sd, buf, strlen(buf));
	printf("%s", buf);

	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	if (!usestdin) {
		strcpy(buf, "Subject: hey\r\n\r\nhey\r\n.\r\n");
		write(sd, buf, strlen(buf));
		printf("%s", buf);
	} else {
		strcpy(buf, "Subject: stdin\r\n\r\n");
		write(sd, buf, strlen(buf));
		printf("%s", buf);

		lp = NULL;
		gln = 0;
		nonl = 0;
		while ((len = getline(&lp, &gln, stdin)) != -1) {
			while (len > 0) {
				n = write(sd, lp, len);
				len -= n;
			}
			printf("%s", lp);
		}
		write(sd, "\r\n.\r\n", 3);
		printf("\r\n.\r\n");
	}

	puts("read okay?");
	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	strcpy(buf, "quit\r\n");
	write(sd, buf, strlen(buf));
	printf("%s", buf);

	n = read(sd, buf, 1024);
	buf[n] = '\0';
	printf("%s", buf);

	exit(0);
}
