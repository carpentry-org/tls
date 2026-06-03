#ifndef CARP_TLS_STREAM_H
#define CARP_TLS_STREAM_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_BUF_SIZE 4096

typedef struct {
  int fd;
  SSL *ssl;
  SSL_CTX *ctx;
} TlsStream;

/* Shared SSL_CTX for client connections. Initialized once. */
static SSL_CTX *carp_tls_client_ctx = NULL;

static SSL_CTX *carp_tls_get_client_ctx(void) {
  if (carp_tls_client_ctx != NULL) return carp_tls_client_ctx;

  const SSL_METHOD *method = TLS_client_method();
  if (!method) return NULL;

  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) return NULL;

  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  carp_tls_client_ctx = ctx;
  return ctx;
}

static String carp_tls_error_string(void) {
  unsigned long e = ERR_get_error();
  if (e == 0) {
    const char *msg = strerror(errno);
    size_t len = strlen(msg);
    String s = CARP_MALLOC(len + 1);
    memcpy(s, msg, len + 1);
    return s;
  }
  char buf[256];
  ERR_error_string_n(e, buf, sizeof(buf));
  size_t len = strlen(buf);
  String s = CARP_MALLOC(len + 1);
  memcpy(s, buf, len + 1);
  return s;
}

TlsStream TlsStream_connect_(String *host, int port) {
  TlsStream s;
  s.fd = -1;
  s.ssl = NULL;
  s.ctx = NULL;

  SSL_CTX *ctx = carp_tls_get_client_ctx();
  if (!ctx) return s;

  /* Resolve and connect TCP */
  struct addrinfo hints, *result, *rp;
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  if (getaddrinfo(*host, port_str, &hints, &result) != 0) return s;

  int fd = -1;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(result);
  if (fd < 0) return s;

  /* Set up SSL */
  SSL *ssl = SSL_new(ctx);
  if (!ssl) { close(fd); return s; }

  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, *host);

  /* Enable hostname verification */
  SSL_set1_host(ssl, *host);

  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl);
    close(fd);
    return s;
  }

  s.fd = fd;
  s.ssl = ssl;
  s.ctx = ctx;
  return s;
}

int TlsStream_fd_(TlsStream *s) { return s->fd; }

int TlsStream_send_(TlsStream *s, String *msg) {
  size_t len = strlen(*msg);
  size_t sent = 0;
  while (sent < len) {
    int n = SSL_write(s->ssl, *msg + sent, (int)(len - sent));
    if (n <= 0) return -1;
    sent += n;
  }
  return (int)sent;
}

int TlsStream_send_MINUS_bytes_(TlsStream *s, Array *data) {
  size_t len = data->len;
  size_t sent = 0;
  while (sent < len) {
    int n = SSL_write(s->ssl, (char *)data->data + sent, (int)(len - sent));
    if (n <= 0) return -1;
    sent += n;
  }
  return (int)sent;
}

int TlsStream_read_(TlsStream *s, String *out) {
  CARP_FREE(*out);
  *out = CARP_MALLOC(TLS_BUF_SIZE + 1);
  int r = SSL_read(s->ssl, *out, TLS_BUF_SIZE);
  if (r > 0) {
    (*out)[r] = '\0';
    return r;
  }
  (*out)[0] = '\0';
  if (r == 0) return 0;
  return r;
}

int TlsStream_read_MINUS_append_(TlsStream *s, Array *buf) {
  if ((int)(buf->capacity - buf->len) < TLS_BUF_SIZE) {
    int new_cap = (buf->len + TLS_BUF_SIZE) * 2;
    buf->data = CARP_REALLOC(buf->data, new_cap);
    buf->capacity = new_cap;
  }
  int r = SSL_read(s->ssl, (char *)buf->data + buf->len, TLS_BUF_SIZE);
  if (r > 0) buf->len += r;
  return r;
}

String TlsStream_error_(void) {
  return carp_tls_error_string();
}

void TlsStream_close(TlsStream s) {
  if (s.ssl) {
    SSL_shutdown(s.ssl);
    SSL_free(s.ssl);
  }
  if (s.fd >= 0) close(s.fd);
}

void TlsStream_close_MINUS_ref(TlsStream *s) {
  if (s->ssl) {
    SSL_shutdown(s->ssl);
    SSL_free(s->ssl);
    s->ssl = NULL;
  }
  if (s->fd >= 0) {
    close(s->fd);
    s->fd = -1;
  }
}

void TlsStream_set_MINUS_timeout(TlsStream *s, int seconds) {
  struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
  setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

TlsStream TlsStream_copy(TlsStream *s) {
  TlsStream c;
  c.fd = (s->fd >= 0) ? dup(s->fd) : -1;
  c.ssl = s->ssl;
  if (c.ssl) SSL_up_ref(c.ssl);
  c.ctx = s->ctx;
  return c;
}

int TlsStream_init_(void) {
  return carp_tls_get_client_ctx() != NULL ? 0 : -1;
}

/* ===================================================================
   Server-side TLS
   =================================================================== */

typedef struct {
  SSL_CTX *ctx;
} TlsServerCtx;

TlsServerCtx TlsServerCtx_create_(String *cert_file, String *key_file) {
  TlsServerCtx sc;
  sc.ctx = NULL;

  const SSL_METHOD *method = TLS_server_method();
  if (!method) return sc;

  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) return sc;

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  if (SSL_CTX_use_certificate_chain_file(ctx, *cert_file) <= 0) {
    SSL_CTX_free(ctx);
    return sc;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, *key_file, SSL_FILETYPE_PEM) <= 0) {
    SSL_CTX_free(ctx);
    return sc;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    SSL_CTX_free(ctx);
    return sc;
  }

  sc.ctx = ctx;
  return sc;
}

int TlsServerCtx_valid_(TlsServerCtx *sc) {
  return sc->ctx != NULL;
}

void TlsServerCtx_close(TlsServerCtx sc) {
  if (sc.ctx) SSL_CTX_free(sc.ctx);
}

void TlsServerCtx_close_MINUS_ref(TlsServerCtx *sc) {
  if (sc->ctx) {
    SSL_CTX_free(sc->ctx);
    sc->ctx = NULL;
  }
}

TlsServerCtx TlsServerCtx_copy(TlsServerCtx *sc) {
  TlsServerCtx c;
  c.ctx = sc->ctx;
  if (c.ctx) SSL_CTX_up_ref(c.ctx);
  return c;
}

TlsStream TlsStream_accept_(TlsServerCtx *sc, int fd) {
  TlsStream s;
  s.fd = -1;
  s.ssl = NULL;
  s.ctx = sc->ctx;

  SSL *ssl = SSL_new(sc->ctx);
  if (!ssl) { close(fd); return s; }

  SSL_set_fd(ssl, fd);

  if (SSL_accept(ssl) != 1) {
    SSL_free(ssl); /* BIO_CLOSE closes fd */
    return s;
  }

  s.fd = fd;
  s.ssl = ssl;
  return s;
}

#endif
