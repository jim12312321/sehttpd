#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "http.h"

/* constant-time string comparison */
#define cst_strcmp(m, c0, c1, c2, c3) \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define CR '\r'
#define LF '\n'
#define CRLFCRLF "\r\n\r\n"

int http_parse_request_line(http_request_t *r)
{
    uint8_t ch, *p, *m;
    size_t pi;

    enum {
        s_start = 0,
        s_method,
        s_spaces_before_uri,
        s_after_slash_in_uri,
        s_http,
        s_http_H,
        s_http_HT,
        s_http_HTT,
        s_http_HTTP,
        s_first_major_digit,
        s_major_digit,
        s_first_minor_digit,
        s_minor_digit,
        s_spaces_after_digit,
        s_almost_done
    } state;
    // cppcheck-suppress syntaxError
    static const void *dispatch_table[] = {&&t_start,
                                           &&t_method,
                                           &&t_spaces_before_uri,
                                           &&t_after_slash_in_uri,
                                           &&t_http,
                                           &&t_http_H,
                                           &&t_http_HT,
                                           &&t_http_HTT,
                                           &&t_http_HTTP,
                                           &&t_first_major_digit,
                                           &&t_major_digit,
                                           &&t_first_minor_digit,
                                           &&t_minor_digit,
                                           &&t_spaces_after_digit,
                                           &&t_almost_done};
#define DISPATCH()                             \
    do {                                       \
        pi++;                                  \
        if (pi >= r->last)                     \
            goto again;                        \
        p = (uint8_t *) &r->buf[pi % MAX_BUF]; \
        ch = *p;                               \
        goto *dispatch_table[state];           \
    } while (0)
    pi = r->pos--;
    state = r->state;
    DISPATCH();

/* HTTP methods: GET, HEAD, POST */
t_start:
    r->request_start = p;

    if (ch == CR || ch == LF)
        DISPATCH();

    if ((ch < 'A' || ch > 'Z') && ch != '_')
        return HTTP_PARSER_INVALID_METHOD;

    state = s_method;
    DISPATCH();

t_method:
    if (ch == ' ') {
        m = r->request_start;

        switch (p - m) {
        case 3:
            if (cst_strcmp(m, 'G', 'E', 'T', ' ')) {
                r->method = HTTP_GET;
                break;
            }
            break;

        case 4:
            if (cst_strcmp(m, 'P', 'O', 'S', 'T')) {
                r->method = HTTP_POST;
                break;
            }

            if (cst_strcmp(m, 'H', 'E', 'A', 'D')) {
                r->method = HTTP_HEAD;
                break;
            }
            break;

        default:
            r->method = HTTP_UNKNOWN;
            break;
        }
        state = s_spaces_before_uri;
        DISPATCH();
    }

    if ((ch < 'A' || ch > 'Z') && ch != '_')
        return HTTP_PARSER_INVALID_METHOD;
    DISPATCH();

/* space* before URI */
t_spaces_before_uri:
    if (ch == '/') {
        r->uri_start = p;
        state = s_after_slash_in_uri;
        DISPATCH();
    }

    if (ch != ' ')
        return HTTP_PARSER_INVALID_REQUEST;

    DISPATCH();

t_after_slash_in_uri:
    if (ch == ' ') {
        r->uri_end = p;
        state = s_http;
    }
    DISPATCH();

/* space+ after URI */
t_http:
    switch (ch) {
    case ' ':
        break;
    case 'H':
        state = s_http_H;
        break;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

t_http_H:
    switch (ch) {
    case 'T':
        state = s_http_HT;
        break;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

t_http_HT:
    switch (ch) {
    case 'T':
        state = s_http_HTT;
        break;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

t_http_HTT:
    switch (ch) {
    case 'P':
        state = s_http_HTTP;
        break;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

t_http_HTTP:
    switch (ch) {
    case '/':
        state = s_first_major_digit;
        break;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

/* first digit of major HTTP version */
t_first_major_digit:
    if (ch < '1' || ch > '9')
        return HTTP_PARSER_INVALID_REQUEST;

    r->http_major = ch - '0';
    state = s_major_digit;
    DISPATCH();

/* major HTTP version or dot */
t_major_digit:
    if (ch == '.') {
        state = s_first_minor_digit;
        DISPATCH();
    }

    if (ch < '0' || ch > '9')
        return HTTP_PARSER_INVALID_REQUEST;

    r->http_major = r->http_major * 10 + ch - '0';
    DISPATCH();

/* first digit of minor HTTP version */
t_first_minor_digit:
    if (ch < '0' || ch > '9')
        return HTTP_PARSER_INVALID_REQUEST;

    r->http_minor = ch - '0';
    state = s_minor_digit;
    DISPATCH();

/* minor HTTP version or end of request line */
t_minor_digit:
    if (ch == CR) {
        state = s_almost_done;
        DISPATCH();
    }

    if (ch == LF)
        goto done;

    if (ch == ' ') {
        state = s_spaces_after_digit;
        DISPATCH();
    }

    if (ch < '0' || ch > '9')
        return HTTP_PARSER_INVALID_REQUEST;

    r->http_minor = r->http_minor * 10 + ch - '0';
    DISPATCH();

t_spaces_after_digit:
    switch (ch) {
    case ' ':
        break;
    case CR:
        state = s_almost_done;
        break;
    case LF:
        goto done;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }
    DISPATCH();

/* end of request line */
t_almost_done:
    r->request_end = p - 1;
    switch (ch) {
    case LF:
        goto done;
    default:
        return HTTP_PARSER_INVALID_REQUEST;
    }

again:
    r->pos = pi;
    r->state = state;

    return EAGAIN;

done:
    r->pos = pi + 1;

    if (!r->request_end)
        r->request_end = p;

    r->state = s_start;

    return 0;
}

int http_parse_request_body(http_request_t *r)
{
    uint8_t ch, *p;
    size_t pi;

    enum {
        s_start = 0,
        s_key,
        s_spaces_before_colon,
        s_spaces_after_colon,
        s_value,
        s_cr,
        s_crlf,
        s_crlfcr
    } state;

    state = r->state;
    assert(state == 0 && "state should be 0");

    static const void *dispatch_table[] = {&&t_start,
                                           &&t_key,
                                           &&t_spaces_before_colon,
                                           &&t_spaces_after_colon,
                                           &&t_value,
                                           &&t_cr,
                                           &&t_crlf,
                                           &&t_crlfcr};
#define DISPATCH()                             \
    do {                                       \
        pi++;                                  \
        if (pi >= r->last)                     \
            goto again;                        \
        p = (uint8_t *) &r->buf[pi % MAX_BUF]; \
        ch = *p;                               \
        goto *dispatch_table[state];           \
    } while (0)
    pi = r->pos--;
    DISPATCH();

    http_header_t *hd;

t_start:
    if (ch != CR && ch != LF) {
        r->cur_header_key_start = p;
        state = s_key;
    }
    DISPATCH();

t_key:
    if (ch == ' ') {
        r->cur_header_key_end = p;
        state = s_spaces_before_colon;
    } else if (ch == ':') {
        r->cur_header_key_end = p;
        state = s_spaces_after_colon;
    }
    DISPATCH();

t_spaces_before_colon:
    switch (ch) {
    case ':':
        state = s_spaces_after_colon;
    case ' ':
        break;
    default:
        return HTTP_PARSER_INVALID_HEADER;
    }
    DISPATCH();

t_spaces_after_colon:
    if (ch != ' ') {
        state = s_value;
        r->cur_header_value_start = p;
    }
    DISPATCH();

t_value:
    if (ch == CR) {
        r->cur_header_value_end = p;
        state = s_cr;
    } else if (ch == LF) {
        r->cur_header_value_end = p;
        state = s_crlf;
    }
    DISPATCH();

t_cr:
    if (ch == LF) {
        state = s_crlf;
        /* save the current HTTP header */
        hd = malloc(sizeof(http_header_t));
        hd->key_start = r->cur_header_key_start;
        hd->key_end = r->cur_header_key_end;
        hd->value_start = r->cur_header_value_start;
        hd->value_end = r->cur_header_value_end;

        list_add(&(hd->list), &(r->list));
        DISPATCH();
    }
    return HTTP_PARSER_INVALID_HEADER;

t_crlf:
    if (ch == CR) {
        state = s_crlfcr;
    } else {
        r->cur_header_key_start = p;
        state = s_key;
    }
    DISPATCH();

t_crlfcr:
    switch (ch) {
    case LF:
        goto done;
    default:
        return HTTP_PARSER_INVALID_HEADER;
    }

again:
    r->pos = pi;
    r->state = state;

    return EAGAIN;

done:
    r->pos = pi + 1;
    r->state = s_start;

    return 0;
}
