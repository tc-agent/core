/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "imap-url.h"

FUZZ_BEGIN_STR(const char *input)
{
	struct imap_url *url;
	const char *error;

	/* Parse as absolute IMAP URL; if valid, regenerate and check round-trip */
	if (imap_url_parse(input, NULL, IMAP_URL_PARSE_ALLOW_URLAUTH,
			   &url, &error) == 0)
		(void)imap_url_create(url);

	/* Parse as relative URL (mailbox path, uid, section etc.) */
	const struct imap_url base = {
		.host = { .name = "example.com" },
		.mailbox = "INBOX",
	};
	(void)imap_url_parse(input, &base,
		IMAP_URL_PARSE_REQUIRE_RELATIVE, &url, &error);
}
FUZZ_END
