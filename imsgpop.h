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

#include <sys/time.h>

#include <event.h>

#define IOBUFLEN	1024

#define MAXARGLEN	40
#define MAXINPUTLEN	(4 + 1 + MAXARGLEN + 2)

enum {
	APRT_NEW_CONN = 1,
	APRT_NEW_USER,
	WRKR_GOAHEAD,
	WRKR_DATA,
	WRKR_DATA_END,
	WRKR_END,
};

enum {
	S_OK,
	S_ERR,
	S_EMPTY,
	S_NUMRS,
};

struct imsgauth {
	uint8_t	ima_prefail;
	char	ima_userbuf[MAXARGLEN + 1];
	char	ima_passbuf[MAXARGLEN + 1];
};
