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

#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

int
main(void) {
	FILE	*fp;
	int	 i;
	char	 hash[_PASSWORD_LEN];

	fp = fopen("/home/me/pop/testauth", "a");

	for (i = 0; i < 10000; ++i) {
		crypt_newhash("password", "bcrypt,a", hash, _PASSWORD_LEN);
		fprintf(fp, "user%04d\t%s\n", i, hash);
	}

	return 0;
}
