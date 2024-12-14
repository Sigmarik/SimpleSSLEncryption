#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const unsigned short PORT = 8080;
static const size_t BUFFER_SIZE = 1024;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() { EVP_cleanup(); }

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    init_openssl();
    SSL_CTX *ctx = create_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    while (connect(sock, (struct sockaddr *)&server_addr,
                   sizeof(server_addr)) != 0);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    const char *msg = "Hello from client!";
    SSL_write(ssl, msg, strlen(msg));

    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    printf("Received: %s\n", buffer);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
