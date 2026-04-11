/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "fuzzer.h"
#include "imap-parser.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *input = test_istream_create_data(data, size);
	struct imap_parser *parser =
		imap_parser_create(input, NULL, 65536, NULL);
	const struct imap_arg *args;
	const char *word;
	int ret;

	i_stream_read(input);

	/* Try to parse as a full IMAP client command: tag SP cmd [args] CRLF */
	ret = imap_parser_read_tag(parser, &word);
	if (ret == 1) {
		ret = imap_parser_read_command_name(parser, &word);
		if (ret == 1)
			(void)imap_parser_finish_line(parser, 0, 0, &args);
	}

	/* Also parse the raw data as a flat argument list with permissive flags */
	imap_parser_reset(parser);
	i_stream_seek(input, 0);
	i_stream_read(input);
	(void)imap_parser_finish_line(parser, 0,
		IMAP_PARSE_FLAG_ATOM_ALLCHARS, &args);

	imap_parser_unref(&parser);
	i_stream_unref(&input);
}
FUZZ_END
