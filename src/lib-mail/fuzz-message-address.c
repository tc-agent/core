/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fuzzer.h"
#include "message-address.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct message_address *addr;
	string_t *str;

	/* Parse as address list and roundtrip through write */
	addr = message_address_parse(pool_datastack_create(), data, size,
				     UINT_MAX, 0);
	if (addr != NULL) {
		str = t_str_new(128);
		message_address_write(str, addr);
		/* Re-parse the written output: must not crash */
		(void)message_address_parse(pool_datastack_create(),
			(const unsigned char *)str_c(str), str_len(str),
			UINT_MAX, 0);
	}

	/* Also exercise Return-Path / path parsing */
	(void)message_address_parse_path(pool_datastack_create(), data, size,
					 &addr);
}
FUZZ_END
