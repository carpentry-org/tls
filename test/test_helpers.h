#ifndef CARP_TLS_TEST_HELPERS_H
#define CARP_TLS_TEST_HELPERS_H

#include <sys/wait.h>
#include <signal.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* ---------------------------------------------------------------
   Self-signed certificate generation
   --------------------------------------------------------------- */

static char carp_test_cert_path[256] = {0};
static char carp_test_key_path[256] = {0};

static int carp_test_generate_cert(void) {
  snprintf(carp_test_cert_path, sizeof(carp_test_cert_path),
           "/tmp/carp_tls_test_cert_%d.pem", getpid());
  snprintf(carp_test_key_path, sizeof(carp_test_key_path),
           "/tmp/carp_tls_test_key_%d.pem", getpid());

  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!kctx) return -1;

  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_keygen_init(kctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
      EVP_PKEY_keygen(kctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    return -1;
  }
  EVP_PKEY_CTX_free(kctx);

  X509 *x509 = X509_new();
  if (!x509) { EVP_PKEY_free(pkey); return -1; }

  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 3600);
  X509_set_pubkey(x509, pkey);

  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                              (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x509, name);

  if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return -1;
  }

  FILE *f = fopen(carp_test_cert_path, "wb");
  if (!f) { X509_free(x509); EVP_PKEY_free(pkey); return -1; }
  PEM_write_X509(f, x509);
  fclose(f);

  f = fopen(carp_test_key_path, "wb");
  if (!f) { X509_free(x509); EVP_PKEY_free(pkey); return -1; }
  PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
  fclose(f);

  X509_free(x509);
  EVP_PKEY_free(pkey);
  return 0;
}

/* Generate a self-signed cert/key pair without forking a server.
   Returns 0 on success, -1 on failure. */
int carp_test_generate_cert_(void) {
  return carp_test_generate_cert();
}

String carp_test_cert_path_(void) {
  size_t len = strlen(carp_test_cert_path);
  String s = CARP_MALLOC(len + 1);
  memcpy(s, carp_test_cert_path, len + 1);
  return s;
}

String carp_test_key_path_(void) {
  size_t len = strlen(carp_test_key_path);
  String s = CARP_MALLOC(len + 1);
  memcpy(s, carp_test_key_path, len + 1);
  return s;
}

/* ---------------------------------------------------------------
   TCP helpers
   --------------------------------------------------------------- */

static int carp_test_listen_port = 0;

static int carp_test_listen(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 1) < 0) {
    close(fd);
    return -1;
  }

  socklen_t len = sizeof(addr);
  getsockname(fd, (struct sockaddr *)&addr, &len);
  carp_test_listen_port = ntohs(addr.sin_port);

  return fd;
}

int carp_test_get_port(void) {
  return carp_test_listen_port;
}

int carp_test_accept_tcp(int listen_fd) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  return accept(listen_fd, (struct sockaddr *)&addr, &len);
}

/* ---------------------------------------------------------------
   Forked TLS echo server
   --------------------------------------------------------------- */

static pid_t carp_test_server_pid = -1;

/* Start a TLS echo server in a child process.
   Accepts one connection, reads one message, echoes it back, exits.
   Returns the port number, or -1 on failure. */
int carp_test_start_echo_server(void) {
  if (carp_test_generate_cert() != 0) return -1;

  int listen_fd = carp_test_listen();
  if (listen_fd < 0) return -1;
  int port = carp_test_listen_port;

  pid_t pid = fork();
  if (pid < 0) { close(listen_fd); return -1; }

  if (pid == 0) {
    /* Child: TLS echo server */
    int client_fd = carp_test_accept_tcp(listen_fd);
    close(listen_fd);
    if (client_fd < 0) _exit(1);

    /* Create server SSL context */
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { close(client_fd); _exit(1); }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_use_certificate_file(ctx, carp_test_cert_path, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, carp_test_key_path, SSL_FILETYPE_PEM);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(client_fd);
      _exit(1);
    }

    /* Echo loop: read one chunk, write it back */
    char buf[TLS_BUF_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0) SSL_write(ssl, buf, n);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(client_fd);
    _exit(0);
  }

  /* Parent */
  carp_test_server_pid = pid;
  close(listen_fd);
  return port;
}

/* ---------------------------------------------------------------
   Insecure client connect (for loopback tests with self-signed certs)
   --------------------------------------------------------------- */

static SSL_CTX *carp_test_insecure_ctx = NULL;

TlsStream carp_test_connect_insecure(int port) {
  TlsStream s;
  s.fd = -1;
  s.ssl = NULL;
  s.ctx = NULL;

  if (!carp_test_insecure_ctx) {
    const SSL_METHOD *method = TLS_client_method();
    carp_test_insecure_ctx = SSL_CTX_new(method);
    if (!carp_test_insecure_ctx) return s;
    SSL_CTX_set_verify(carp_test_insecure_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(carp_test_insecure_ctx, TLS1_2_VERSION);
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return s;

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return s;
  }

  SSL *ssl = SSL_new(carp_test_insecure_ctx);
  SSL_set_fd(ssl, fd);

  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl);
    close(fd);
    return s;
  }

  s.fd = fd;
  s.ssl = ssl;
  s.ctx = carp_test_insecure_ctx;
  return s;
}

/* ---------------------------------------------------------------
   Cleanup
   --------------------------------------------------------------- */

void carp_test_cleanup(void) {
  if (carp_test_server_pid > 0) {
    /* Defensive: kill before reaping so a child stuck in accept() (e.g. a
       test that forked the server but never connected) cannot deadlock the
       suite. Harmless if the child has already exited. */
    kill(carp_test_server_pid, SIGKILL);
    int status;
    waitpid(carp_test_server_pid, &status, 0);
    carp_test_server_pid = -1;
  }
  if (carp_test_cert_path[0]) {
    unlink(carp_test_cert_path);
    carp_test_cert_path[0] = 0;
  }
  if (carp_test_key_path[0]) {
    unlink(carp_test_key_path);
    carp_test_key_path[0] = 0;
  }
}

int carp_test_stream_ok(TlsStream *s) {
  return s->fd >= 0;
}

#endif
