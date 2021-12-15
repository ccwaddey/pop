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

#include "logutil.h"

unsigned int	debuglevel = 0;
int		daemonize = 1;

void
log_init(const char *cp) {
	openlog(cp, LOG_PID | LOG_PERROR, LOG_MAIL);
}

void
lerrx(int e, const char *fmt, ...) {
	va_list ap;

	/* This would be dumb but it could happen */
	if (fmt == NULL) {
		syslog(LOG_ERR, "");
		exit(e);
	}
	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
	exit(e);
}

void
lerr(int e, const char *fmt, ...) {
	va_list	 ap;
	char	*cp1 = NULL, *cp2 = NULL;
	int	 nullfmt = (fmt == NULL);
	int	 sverrno;

	sverrno = errno;
	va_start(ap, fmt);
	if (!nullfmt) {
		vasprintf(&cp1, fmt, ap);
		asprintf(&cp2, "%s: %s", cp1, strerror(sverrno));
		syslog(LOG_DEBUG, "%s", cp2);
	} else {
		syslog(LOG_ERR, "%s", strerror(sverrno));
	}
	va_end(ap);
	free(cp1);
	free(cp2);
	exit(e);
}

void
dlog(unsigned int level, const char *fmt, ...) {
	va_list	ap;

	if (level > debuglevel || fmt == NULL)
		return;

	va_start(ap, fmt);
	vsyslog(level ? LOG_DEBUG : LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}
