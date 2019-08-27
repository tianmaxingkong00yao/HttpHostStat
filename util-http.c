#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util-http.h"

/** max http length */
#define HTTP_MAX_LEN 2048

/** MAGIC determines the number of bytes of the HTTP message body that
 * will be grabbed off of the wire; the idea here is that the initial
 * bytes of that field may contain the file "magic number" that can
 * identify its type
 */
#define MAGIC 16

#define PARSE_FAIL (-1)

void http_free_message(struct http_message *msg)
{
	int k = 0;

	if (msg == NULL) {
		return;
	}

	if (msg->header.line_type == HTTP_LINE_STATUS) {
		struct http_header_status_line *line = &msg->header.line.status;

		if (line->version) {
			free(line->version);
		}
		if (line->code) {
			free(line->code);
		}
		if (line->reason) {
			free(line->reason);
		}
	}
	else if (msg->header.line_type == HTTP_LINE_REQUEST) {
		struct http_header_request_line *line = &msg->header.line.request;

		if (line->method) {
			free(line->method);
		}
		if (line->uri) {
			free(line->uri);
		}
		if (line->version) {
			free(line->version);
		}
	}

	for (k = 0; k < msg->header.num_elements; k++) {
		struct http_header_element *elem = &msg->header.elements[k];

		if (elem->name) {
			free(elem->name);
		}
		if (elem->value) {
			free(elem->value);
		}
	}

	if (msg->body) {
		free(msg->body);
	}

	memset(msg, 0, sizeof(struct http_message));
}

/* ************************
 * **********************
 * Internal Functions
 * **********************
 * ************************
 */

 /*
  * From RFC 2616, Section 4.1:
  *
  *      generic-message = start-line
  *                         *(message-header CRLF)
  *                         CRLF
  *                         [ message-body ]
  *
  *      start-line      = Request-Line | Status-Line
  *
  *      Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
  *
  *      Method         = "OPTIONS"                ; Section 9.2
  *                     | "GET"                    ; Section 9.3
  *                     | "HEAD"                   ; Section 9.4
  *                     | "POST"                   ; Section 9.5
  *                     | "PUT"                    ; Section 9.6
  *                     | "DELETE"                 ; Section 9.7
  *                     | "TRACE"                  ; Section 9.8
  *                     | "CONNECT"                ; Section 9.9
  *                     | extension-method
  *      extension-method = token
  *
  *      Request-URI    = "*" | absoluteURI | abs_path | authority
  *
  *      Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
  *
  *     Status-Code    =
  *           "100"  ; Section 10.1.1: Continue
  *         | "101"  ; Section 10.1.2: Switching Protocols
  *         | "200"  ; Section 10.2.1: OK
  *         | "201"  ; Section 10.2.2: Created
  *         | "202"  ; Section 10.2.3: Accepted
  *         | "203"  ; Section 10.2.4: Non-Authoritative Information
  *         | "204"  ; Section 10.2.5: No Content
  *         | "205"  ; Section 10.2.6: Reset Content
  *         | "206"  ; Section 10.2.7: Partial Content
  *         | "300"  ; Section 10.3.1: Multiple Choices
  *         | "301"  ; Section 10.3.2: Moved Permanently
  *         | "302"  ; Section 10.3.3: Found
  *         | "303"  ; Section 10.3.4: See Other
  *         | "304"  ; Section 10.3.5: Not Modified
  *         | "305"  ; Section 10.3.6: Use Proxy
  *         | "307"  ; Section 10.3.8: Temporary Redirect
  *         | "400"  ; Section 10.4.1: Bad Request
  *         | "401"  ; Section 10.4.2: Unauthorized
  *         | "402"  ; Section 10.4.3: Payment Required
  *         | "403"  ; Section 10.4.4: Forbidden
  *         | "404"  ; Section 10.4.5: Not Found
  *         | "405"  ; Section 10.4.6: Method Not Allowed
  *         | "406"  ; Section 10.4.7: Not Acceptable
  *         | "407"  ; Section 10.4.8: Proxy Authentication Required
  *         | "408"  ; Section 10.4.9: Request Time-out
  *         | "409"  ; Section 10.4.10: Conflict
  *         | "410"  ; Section 10.4.11: Gone
  *         | "411"  ; Section 10.4.12: Length Required
  *         | "412"  ; Section 10.4.13: Precondition Failed
  *         | "413"  ; Section 10.4.14: Request Entity Too Large
  *         | "414"  ; Section 10.4.15: Request-URI Too Large
  *         | "415"  ; Section 10.4.16: Unsupported Media Type
  *         | "416"  ; Section 10.4.17: Requested range not satisfiable
  *         | "417"  ; Section 10.4.18: Expectation Failed
  *         | "500"  ; Section 10.5.1: Internal Server Error
  *         | "501"  ; Section 10.5.2: Not Implemented
  *         | "502"  ; Section 10.5.3: Bad Gateway
  *         | "503"  ; Section 10.5.4: Service Unavailable
  *         | "504"  ; Section 10.5.5: Gateway Time-out
  *         | "505"  ; Section 10.5.6: HTTP Version not supported
  *         | extension-code
  *
  *     extension-code = 3DIGIT
  *     Reason-Phrase  = *<TEXT, excluding CR, LF>
  *
  */

enum parse_state {
	non_crlf = 0,
	first_cr = 1,
	first_lf = 2,
	second_cr = 3,
	second_lf = 4
};

static unsigned int memcpy_up_to_crlfcrlf_plus_magic(char *dst, const char *src, unsigned int length) {
	unsigned int i;
	enum parse_state state = non_crlf;
	unsigned int body_bytes = 0;

	for (i = 0; i < length; ++i) {
		/* reached the end of the src without finding crlfcrlf */
		if (i == (length - MAGIC)) {
			break;
		}

		/* copy the byte to destination */
		*(dst + i) = *(src + i);

		/*  found a CRLFCRLF; copy magic bytes of body then return */
		if (state == second_lf) {
			if (body_bytes < MAGIC) {
				// printf("body_bytes: %u\tMAGIC: %u\ti: %u\tlength: %u\n", body_bytes, MAGIC, i, length);
				++body_bytes;
			}
			else {
				break;
			}
		}

		/* still parsing HTTP headers */
		else {
			/*
			 * make string printable, by suppressing characters below SPACE
			 * (32) and above DEL (127), inclusive, except for \r and \n
			 */
			if ((*(dst + i) < 32 || *(dst + i) > 126) && *(dst + i) != '\r' && *(dst + i) != '\n') {
				*(dst + i) = '.';
			}
			/* avoid JSON confusion */
			if ((*(dst + i) == '"') || (*(dst + i) == '\\')) {
				*(dst + i) = '.';
			}

			/* advance lexer state  */
			if (*(src + i) == '\r') {
				if (state == non_crlf) {
					state = first_cr;
				}
				else if (state == first_lf) {
					state = second_cr;
				}
			}
			else if (*(src + i) == '\n') {
				if (state == first_cr) {
					state = first_lf;
				}
				else if (state == second_cr) {
					state = second_lf;
				}
			}
			else {
				if (state != second_lf) {
					state = non_crlf;
				}
			}
		}

	}

	return i;
}

/****************************
 * Lexer for http headers
 ****************************
 */

enum http_type {
	http_done = 0,
	http_method = 1,
	http_header = 2,
	http_request_line = 3,
	http_status_line = 4,
	http_malformed = 5
};

enum header_state {
	got_nothing = 0,
	got_header = 1,
	got_value = 2
};

static enum http_type http_get_next_line(char **saveptr,
	unsigned int *length, char **token1, char **token2) {
	unsigned int i;
	enum parse_state state = non_crlf;
	enum header_state header_state = got_nothing;
	char *src = *saveptr;

	if (src == NULL) {
		return http_done;
	}

	*token1 = src;
	*token2 = NULL;
	for (i = 0; i < *length; i++) {

		/* advance lexer state  */
		if (src[i] == '\r') {
			if (state == non_crlf) {
				state = first_cr;
			}
			else if (state == first_lf) {
				state = second_cr;
			}
			src[i] = '.';  /* make printable, as a precaution */

		}
		else if (src[i] == '\n') {
			if (state == first_cr) {
				state = first_lf;
			}
			else if (state == second_cr) {
				state = second_lf;
			}
			src[i] = '.';  /* make printable, as a precaution */

		}
		else if (src[i] == ':') {
			if (header_state == got_nothing) {
				src[i] = 0;      /* NULL terminate token */
				header_state = got_header;
			}
			state = non_crlf;
		}
		else if (src[i] == ' ') {
			;     /* ignore whitespace */
		}
		else {

			if (state == first_lf) {
				if (header_state == got_value) {
					src[i - 2] = 0;    /* NULL terminate token */
					*length = *length - i;
					*saveptr = &src[i];
					return http_header;
				}
				else {
					/* Missing the complete name/value pair */
					return http_malformed;
				}
			}

			if (header_state == got_header) {
				*token2 = &src[i];
				header_state = got_value;
			}
			state = non_crlf;
		}

		if (state == second_lf) {
			src[i - 3] = 0;   /* NULL terminate token */
			/*
			 * move past the last lf token to set the pointer
			 * at the beginning of the body and set the length
			 * to be just of the remaining body bytes, if any.
			 */
			*length = *length - i - 1;
			*saveptr = &src[i + 1];
			return http_done;
		}
	}

	*saveptr = NULL;
	return http_malformed;
}

enum start_line_state {
	got_none = 0,
	got_first = 1,
	started_second = 2,
	got_second = 3,
	started_third = 4,
	got_third = 5
};

static enum http_type http_get_start_line(char **saveptr,
	unsigned int *length, char **token1,
	char **token2, char **token3) {
	unsigned int i;
	enum parse_state state = non_crlf;
	enum start_line_state start_state = got_none;
	char last_char = 0;
	enum http_type line_type = http_request_line;
	char *src = *saveptr;

	if (src == NULL) {
		return http_done;
	}

	*token1 = src;
	*token2 = *token3 = NULL;
	for (i = 0; i < *length; i++) {

		/* advance lexer state  */
		if (src[i] == '\r') {
			if (state == non_crlf) {
				state = first_cr;
			}
			else if (state == first_lf) {
				state = second_cr;
			}
			src[i] = '.';  /* make printable, as a precaution */

		}
		else if (src[i] == '\n') {
			if (state == first_cr) {
				state = first_lf;
			}
			else if (state == second_cr) {
				state = second_lf;
			}
			src[i] = '.';  /* make printable, as a precaution */

		}
		else if (src[i] == ' ') {
			if (start_state == got_none) {
				start_state = got_first;
			}
			else if (start_state == started_second) {
				start_state = got_second;
			}
			state = non_crlf;
		}
		else {

			if (state == first_lf) {
				src[i - 2] = 0;      /* NULL terminate token */
				*length = *length - i;
				*saveptr = &src[i];
				if (start_state == started_third) {
					return line_type;
				}
				else {
					return http_malformed;
				}
			}

			if (start_state == got_none) {
				/*
				 * check for string "HTTP", which indicates a status line (not a response line)
				 */
				if (last_char == 0 && src[i] == 'H') {
					last_char = 'H';
				}
				else if ((last_char == 'H' || last_char == 'T') && src[i] == 'T') {
					last_char = 'T';
				}
				else if (last_char == 'T' && src[i] == 'P') {
					line_type = http_status_line;
				}
			}
			else if (start_state == got_first) {
				src[i - 1] = 0;      /* NULL terminate token */
				*token2 = &src[i];
				start_state = started_second;
			}
			else if (start_state == got_second) {
				src[i - 1] = 0;      /* NULL terminate token */
				*token3 = &src[i];
				start_state = started_third;
			}
			state = non_crlf;
		}

		if (state == second_lf) {
			src[i - 3] = 0;        /* NULL terminate token */
			*length = *length - i;
			*saveptr = &src[i];
			return http_done;
		}
	}

	*saveptr = NULL;
	return http_malformed;
}

static int http_header_select(char *h) {
	int rc = 0;
	if (h != NULL) {
		rc = 1;
	}
	return rc;
}

#define PRINT_USERNAMES 1
#define MAX_STRLEN 2048

static int http_parse_message(struct http_message *msg,
	char *data,
	unsigned int length)
{

	struct http_header *hdr = NULL;
	char *token1, *token2, *token3, *saveptr = NULL;
	enum http_type type = http_done;
	unsigned int str_len = 0;
	int i = 0;
	int rc = 0;

	if (length < 4) {
		return PARSE_FAIL;
	}

	if (msg == NULL) {
		return PARSE_FAIL;
	}

	/*
	 * Parse start-line, and get request/status lines.
	 */
	saveptr = data;

	/* Easy access to the header storage */
	hdr = &msg->header;

	/* Try to get the start line of (header) data */
	type = http_get_start_line(&saveptr, &length, &token1, &token2, &token3);

	if (type == http_malformed) {
		return PARSE_FAIL;
	}

	if (type == http_request_line) {
		hdr->line_type = HTTP_LINE_REQUEST;

		str_len = strnlen(token1, MAX_STRLEN);
		hdr->line.request.method = calloc(str_len + 1, sizeof(char));
		if (hdr->line.request.method == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.request.method, str_len + 1, token1);

		str_len = strnlen(token2, MAX_STRLEN);
		hdr->line.request.uri = calloc(str_len + 1, sizeof(char));
		if (hdr->line.request.uri == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.request.uri, str_len + 1, token2);

		str_len = strnlen(token3, MAX_STRLEN);
		hdr->line.request.version = calloc(str_len + 1, sizeof(char));
		if (hdr->line.request.version == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.request.version, str_len + 1, token3);

	}
	else if (type == http_status_line) {
		hdr->line_type = HTTP_LINE_STATUS;

		str_len = strnlen(token1, MAX_STRLEN);
		hdr->line.status.version = calloc(str_len + 1, sizeof(char));
		if (hdr->line.status.version == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.status.version, str_len + 1, token1);

		str_len = strnlen(token2, MAX_STRLEN);
		hdr->line.status.code = calloc(str_len + 1, sizeof(char));
		if (hdr->line.status.code == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.status.code, str_len + 1, token2);

		str_len = strnlen(token3, MAX_STRLEN);
		hdr->line.status.reason = calloc(str_len + 1, sizeof(char));
		if (hdr->line.status.reason == NULL) {

			rc = PARSE_FAIL;
			goto end;
		}
		strcpy_s(hdr->line.status.reason, str_len + 1, token3);
	}

	if (type != http_done) {
		/*
		 * Get the header elements
		 */
		for (i = 0; i < HTTP_MAX_HEADER_ELEMENTS; i++) {
			type = http_get_next_line(&saveptr, &length, &token1, &token2);

			if (!(type == http_header || (type == http_done && token1 && token2))) {
				if (type == http_malformed) {
					rc = PARSE_FAIL;
					goto end;
				}
				break;
			}

			if (http_header_select(token1)) {
				struct http_header_element *elem = &hdr->elements[hdr->num_elements];

				str_len = strnlen(token1, MAX_STRLEN);
				if (str_len == 0) {
					if (type == http_done) {
						break;
					}
					else {
						continue;
					}
				}

				elem->name = calloc(str_len + 1, sizeof(char));
				if (elem->name == NULL) {

					rc = 1;
					goto end;
				}
				strcpy_s(elem->name, str_len + 1, token1);

				str_len = strnlen(token2, MAX_STRLEN);
				elem->value = calloc(str_len + 1, sizeof(char));
				if (elem->value == NULL) {

					/* Don't want a dangling name */
					free(elem->name); elem->name = NULL;
					rc = 1;
					goto end;
				}
				strcpy_s(elem->value, str_len + 1, token2);

				/* Increment number of header elements */
				hdr->num_elements++;
			}

			/* End of headers */
			if (type == http_done) break;
		}
	}

	/*
	 * Copy the initial "MAGIC" bytes of the HTTP body
	 */
	if (type == http_done && (MAGIC != 0) && (length >= MAGIC)) {
		msg->body = calloc(MAGIC, sizeof(char));
		if (msg->body == NULL) {

			rc = 1;
			goto end;
		}

		memcpy(msg->body, saveptr, MAGIC);
		msg->body_length = MAGIC;
	}

end:
	if (rc == PARSE_FAIL) {
		/*
		 * Failed to properly parse the message.
		 * Free any memory that was allocated.
		 */
		http_free_message(msg);
	}

	return rc;
}

void http_print_message(FILE *f, const struct http_message *msg)
{
	int i = 0;

	if (msg->header.line_type == HTTP_LINE_STATUS) {
		const struct http_header_status_line *line = &msg->header.line.status;

		fprintf(f, "----- Respone -----\n"
			"version: %s\n"
			"code: %s\n"
			"reason: %s\n",
			line->version, line->code, line->reason);
	}
	else if (msg->header.line_type == HTTP_LINE_REQUEST) {
		const struct http_header_request_line *line = &msg->header.line.request;

		fprintf(f, "----- Request -----\n"
			"method: %s\n"
			"uri: %s\n"
			"version: %s\n",
			line->method, line->uri, line->version);

	}

	fprintf(f, "[ Header Element ]\n");
	for (i = 0; i < msg->header.num_elements; i++) {
		const struct http_header_element *elem = &msg->header.elements[i];

		if (elem->name && elem->value) {
			fprintf(f, "%s: %s\n", elem->name, elem->value);
		}
	}

	/*
	 * Print out the body
	 */
	if (msg->body) {


	}

}

int process_http(struct http_message *msg, const uint8_t *data, uint32_t data_len)
{
	char *raw_header = NULL;
	unsigned int tmp_len = 0;
	int success = -1, rc = 0;

	memset(msg, 0, sizeof(*msg));

	if (data == NULL || data_len == 0)
		return -1;

	tmp_len = (data_len + MAGIC) < HTTP_MAX_LEN ? (data_len + MAGIC) : HTTP_MAX_LEN;
	/* Temporary buffer for holding header */
	raw_header = calloc(HTTP_MAX_LEN, sizeof(char));
	if (raw_header == NULL) {

		return -1;
	}

	/* Copy the header plus magic */
	rc = memcpy_up_to_crlfcrlf_plus_magic(raw_header, data, tmp_len);
	if (rc == 0) {
		/* No data to parse */
		goto leave;
	}

	/*
	 * Sift through the header.
	 */
	rc = http_parse_message(msg, raw_header, tmp_len);
	if (rc != PARSE_FAIL) {
		/* Parsing was a success */
		success = 0;
	}

leave:
	if (raw_header) {
		free(raw_header);
		raw_header = NULL;
	}

	return success;
}
