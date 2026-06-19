#ifndef CARP_TLS_STREAM_H
#define CARP_TLS_STREAM_H

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

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

/* Defense-in-depth options applied to every context: disable client-initiated
   renegotiation (TLS 1.2; TLS 1.3 has none) and TLS-level compression (CRIME,
   CVE-2012-4929). #ifdef-guarded so this still builds against LibreSSL/older
   OpenSSL that lack the flags. */
static void carp_tls_harden_ctx(SSL_CTX *ctx) {
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif
#ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
}

static SSL_CTX *carp_tls_get_client_ctx(void) {
  if (carp_tls_client_ctx != NULL) return carp_tls_client_ctx;

  const SSL_METHOD *method = TLS_client_method();
  if (!method) return NULL;

  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) return NULL;

  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  carp_tls_harden_ctx(ctx);

  carp_tls_client_ctx = ctx;
  return ctx;
}

/* Last error message, captured at the failure site (before any SSL_free/close
   that would reset errno or drain the OpenSSL error queue). Process-global,
   matching the single-threaded assumption of the rest of the library. */
static char carp_tls_last_error[256] = {0};

static void carp_tls_set_error(const char *msg) {
  if (!msg) msg = "unknown error";
  size_t n = strlen(msg);
  if (n >= sizeof(carp_tls_last_error)) n = sizeof(carp_tls_last_error) - 1;
  memcpy(carp_tls_last_error, msg, n);
  carp_tls_last_error[n] = '\0';
}

/* Capture the current OpenSSL/system error into carp_tls_last_error. ssl_err is
   the result of SSL_get_error at the failure site (pass SSL_ERROR_SSL when there
   is no SSL* yet, e.g. SSL_new / SSL_CTX_* failures). Drains the error queue so
   a stale entry cannot leak into a later capture. */
static void carp_tls_capture_ssl_error(int ssl_err) {
  unsigned long e = ERR_get_error();
  if (e != 0) {
    ERR_error_string_n(e, carp_tls_last_error, sizeof(carp_tls_last_error));
  } else if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
    carp_tls_set_error(strerror(errno));
  } else if (ssl_err == SSL_ERROR_SYSCALL) {
    carp_tls_set_error("unexpected EOF (no close_notify)");
  } else {
    carp_tls_set_error("TLS protocol error");
  }
  ERR_clear_error();
}

TlsStream TlsStream_connect_(String *host, int port) {
  TlsStream s;
  s.fd = -1;
  s.ssl = NULL;
  s.ctx = NULL;

  SSL_CTX *ctx = carp_tls_get_client_ctx();
  if (!ctx) {
    carp_tls_set_error("could not initialize TLS client context");
    return s;
  }

  /* Resolve and connect TCP */
  struct addrinfo hints, *result, *rp;
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  int gai = getaddrinfo(*host, port_str, &hints, &result);
  if (gai != 0) {
    carp_tls_set_error(gai_strerror(gai));
    return s;
  }

  int fd = -1;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  if (fd < 0) carp_tls_set_error(strerror(errno));
  freeaddrinfo(result);
  if (fd < 0) return s;

  /* Set up SSL */
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
    close(fd);
    return s;
  }

  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, *host);

  /* Enable hostname verification. If this fails we would still trust the chain
     but skip the name check (fail-open), so bail out instead. */
  if (SSL_set1_host(ssl, *host) != 1) {
    carp_tls_set_error("could not enable hostname verification");
    SSL_free(ssl);
    close(fd);
    return s;
  }

  int rc = SSL_connect(ssl);
  if (rc != 1) {
    carp_tls_capture_ssl_error(SSL_get_error(ssl, rc));
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

/* SSL_write takes an int length, so clamp each call to INT_MAX rather than
   truncating a size_t remaining into a (possibly negative) int. */
static int carp_tls_write_chunk(size_t remaining) {
  return remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
}

int TlsStream_send_(TlsStream *s, String *msg) {
  size_t len = strlen(*msg);
  size_t sent = 0;
  while (sent < len) {
    int n = SSL_write(s->ssl, *msg + sent, carp_tls_write_chunk(len - sent));
    if (n <= 0) {
      carp_tls_capture_ssl_error(SSL_get_error(s->ssl, n));
      return -1;
    }
    sent += n;
  }
  return sent > (size_t)INT_MAX ? INT_MAX : (int)sent;
}

int TlsStream_send_MINUS_bytes_(TlsStream *s, Array *data) {
  size_t len = data->len;
  size_t sent = 0;
  while (sent < len) {
    int n = SSL_write(s->ssl, (char *)data->data + sent,
                      carp_tls_write_chunk(len - sent));
    if (n <= 0) {
      carp_tls_capture_ssl_error(SSL_get_error(s->ssl, n));
      return -1;
    }
    sent += n;
  }
  return sent > (size_t)INT_MAX ? INT_MAX : (int)sent;
}

/* Classify an SSL_read result <= 0 into a status code:
   0  = clean shutdown (peer sent close_notify)
   -1 = error (fatal, syscall, timeout, truncation, ...) */
static int carp_tls_read_status(SSL *ssl, int r) {
  int err = SSL_get_error(ssl, r);
  if (err == SSL_ERROR_ZERO_RETURN) return 0;
  carp_tls_capture_ssl_error(err);
  return -1;
}

/* Reads up to TLS_BUF_SIZE bytes. *status is set to the number of bytes read
   (> 0), 0 on clean close, or -1 on error. */
String TlsStream_read_(TlsStream *s, int *status) {
  String buf = CARP_MALLOC(TLS_BUF_SIZE + 1);
  int r = SSL_read(s->ssl, buf, TLS_BUF_SIZE);
  if (r > 0) {
    buf[r] = '\0';
    *status = r;
    return buf;
  }
  buf[0] = '\0';
  *status = carp_tls_read_status(s->ssl, r);
  return buf;
}

Array TlsStream_read_MINUS_bytes_(TlsStream *s, int *status) {
  Array buf;
  buf.capacity = TLS_BUF_SIZE;
  buf.data = CARP_MALLOC(TLS_BUF_SIZE);
  int r = SSL_read(s->ssl, buf.data, TLS_BUF_SIZE);
  if (r > 0) {
    buf.len = r;
    *status = r;
    return buf;
  }
  buf.len = 0;
  *status = carp_tls_read_status(s->ssl, r);
  return buf;
}

int TlsStream_read_MINUS_append_(TlsStream *s, Array *buf) {
  if (buf->capacity - buf->len < (size_t)TLS_BUF_SIZE) {
    /* size_t throughout: len/capacity are size_t, so the old int new_cap
       overflowed once a buffer passed ~2GB, corrupting capacity. */
    size_t new_cap = (buf->len + (size_t)TLS_BUF_SIZE) * 2;
    void *grown = CARP_REALLOC(buf->data, new_cap);
    if (!grown) {
      /* realloc leaves the original block valid; keep buf intact and report. */
      carp_tls_set_error("out of memory growing read buffer");
      return -1;
    }
    buf->data = grown;
    buf->capacity = new_cap;
  }
  int r = SSL_read(s->ssl, (char *)buf->data + buf->len, TLS_BUF_SIZE);
  if (r > 0) {
    buf->len += r;
    return r;
  }
  return carp_tls_read_status(s->ssl, r);
}

String TlsStream_error_(void) {
  const char *msg = carp_tls_last_error[0] ? carp_tls_last_error : "unknown error";
  size_t len = strlen(msg);
  String s = CARP_MALLOC(len + 1);
  memcpy(s, msg, len + 1);
  return s;
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

void TlsStream_set_MINUS_nonblocking(TlsStream *s) {
  int flags = fcntl(s->fd, F_GETFL, 0);
  if (flags >= 0) fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);
}

/* Non-blocking send. Attempts a single SSL_write from `data` starting at
 * `offset`. Handles SSL_ERROR_WANT_WRITE and SSL_ERROR_WANT_READ (TLS
 * renegotiation) by returning 0 (would-block).
 *
 * Returns:
 *   > 0  bytes actually written
 *     0  would block, retry on next writable/readable event
 *   -1   error (captured in carp_tls_last_error)
 */
int TlsStream_send_MINUS_nb_(TlsStream *s, Array *data, int offset) {
  if (offset >= (int)data->len) return 0;
  int n = SSL_write(s->ssl, (char *)data->data + offset,
                    carp_tls_write_chunk(data->len - (size_t)offset));
  if (n > 0) return n;
  int err = SSL_get_error(s->ssl, n);
  if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) return 0;
  carp_tls_capture_ssl_error(err);
  return -1;
}

/* Non-blocking append-read. Reads whatever SSL has buffered/available into
 * `buf`, growing it as needed. Handles SSL_ERROR_WANT_READ and
 * SSL_ERROR_WANT_WRITE by returning -2 (would-block sentinel matching the
 * sockets library convention).
 *
 * Returns:
 *   > 0  bytes appended
 *     0  peer closed cleanly (close_notify)
 *   -1   error (captured in carp_tls_last_error)
 *   -2   would block, retry on next readable/writable event
 */
int TlsStream_read_MINUS_append_MINUS_nb_(TlsStream *s, Array *buf) {
  if (buf->capacity - buf->len < (size_t)TLS_BUF_SIZE) {
    size_t new_cap = (buf->len + (size_t)TLS_BUF_SIZE) * 2;
    void *grown = CARP_REALLOC(buf->data, new_cap);
    if (!grown) {
      carp_tls_set_error("out of memory growing read buffer");
      return -1;
    }
    buf->data = grown;
    buf->capacity = new_cap;
  }
  int r = SSL_read(s->ssl, (char *)buf->data + buf->len, TLS_BUF_SIZE);
  if (r > 0) {
    buf->len += r;
    return r;
  }
  int err = SSL_get_error(s->ssl, r);
  if (err == SSL_ERROR_ZERO_RETURN) return 0;
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -2;
  carp_tls_capture_ssl_error(err);
  return -1;
}

TlsStream TlsStream_copy(TlsStream *s) {
  TlsStream c;
  c.fd = s->fd;
  c.ssl = s->ssl;
  c.ctx = s->ctx;
  return c;
}

int TlsStream_init_(void) {
  /* A write to a peer that has closed/reset the connection otherwise raises
     SIGPIPE and kills the whole process; ignore it so SSL_write returns an
     error instead. Runs once at load via the module's auto-init. */
  signal(SIGPIPE, SIG_IGN);
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
  if (!method) {
    carp_tls_set_error("could not create TLS server method");
    return sc;
  }

  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
    return sc;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  carp_tls_harden_ctx(ctx);

  if (SSL_CTX_use_certificate_chain_file(ctx, *cert_file) <= 0) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
    SSL_CTX_free(ctx);
    return sc;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, *key_file, SSL_FILETYPE_PEM) <= 0) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
    SSL_CTX_free(ctx);
    return sc;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
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

/* Takes ownership of fd: on success the returned stream owns it (closed by
   TlsStream_close); on failure fd is closed here. Either way the caller must
   not close fd itself. */
TlsStream TlsStream_accept_(TlsServerCtx *sc, int fd) {
  TlsStream s;
  s.fd = -1;
  s.ssl = NULL;
  s.ctx = sc->ctx;

  SSL *ssl = SSL_new(sc->ctx);
  if (!ssl) {
    carp_tls_capture_ssl_error(SSL_ERROR_SSL);
    close(fd);
    return s;
  }

  SSL_set_fd(ssl, fd);

  int rc = SSL_accept(ssl);
  if (rc != 1) {
    carp_tls_capture_ssl_error(SSL_get_error(ssl, rc));
    SSL_free(ssl);
    close(fd);
    return s;
  }

  s.fd = fd;
  s.ssl = ssl;
  return s;
}

#endif
