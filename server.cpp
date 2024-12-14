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

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *crt_name,
                       const char *key_name) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, crt_name, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_name, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void keylog_callback(const SSL *ssl, const char *line) {
    FILE *keylog_file = fopen(getenv("SSLKEYLOGFILE"), "a");
    if (keylog_file) {
        fprintf(keylog_file, "%s\n", line);
        fclose(keylog_file);
    } else {
        perror("Failed to open keylog file");
    }
}

void configure_logging(const char *logfile_name) {
    FILE *file = fopen(logfile_name, "w");
    fclose(file);

    static char buffer[BUFFER_SIZE + 1] = "";
    memset(buffer, 0, BUFFER_SIZE);

    getcwd(buffer, BUFFER_SIZE);
    strncat(buffer, "/", BUFFER_SIZE);
    strncat(buffer, logfile_name, BUFFER_SIZE);

    setenv("SSLKEYLOGFILE", buffer, 1);

    printf("Key log file: %s\n", getenv("SSLKEYLOGFILE"));
}

int main(int argc, char **argv) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[BUFFER_SIZE];

    const char *crt_name = "server.crt";
    const char *key_name = "server.key";

    if (argc > 2) {
        crt_name = argv[1];
        key_name = argv[2];
    }

    configure_logging(argc > 3 ? argv[3] : "sslkeys.log");

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx, crt_name, key_name);

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("Server listening on port %d...\n", PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    SSL_accept(ssl);

    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    printf("Received: %s\n", buffer);

    const char *reply = "Hello from server!";
    SSL_write(ssl, reply, strlen(reply));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
