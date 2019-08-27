#pragma once

enum http_line_type {
	HTTP_LINE_INVALID = 0,
	HTTP_LINE_REQUEST = 1,
	HTTP_LINE_STATUS = 2,
};

struct http_header_status_line {
	char *version;
	char *code;
	char *reason;
};

struct http_header_request_line {
	char *method;
	char *uri;
	char *version;
};

struct http_header_element {
	char *name;
	char *value;
};

#define HTTP_MAX_HEADER_ELEMENTS 32

struct http_header {
	union {
		struct http_header_status_line status;
		struct http_header_request_line request;
	} line;
	enum http_line_type line_type;
	struct http_header_element elements[HTTP_MAX_HEADER_ELEMENTS];
	uint8_t num_elements;
};

struct http_message {
	struct http_header header;
	char *body;
	uint32_t body_length;
};

#define HTTP_MAX_MESSAGES 16

/** http data structure */
typedef struct http {
	uint16_t num_messages;
	struct http_message messages[HTTP_MAX_MESSAGES];
} http_t;


int process_http(struct http_message *msg, const uint8_t *data, uint32_t data_len);

void http_print_message(FILE *f, const struct http_message *msg);

void http_free_message(struct http_message *msg);


