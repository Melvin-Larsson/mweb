#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include <openssl/types.h>
#include <sys/types.h>
#include "stdbool.h"

typedef struct TlsServer TlsServer;

typedef struct{
    ssize_t index;
    uint64_t generation;
    uint8_t worker;
}TlsServerClient;

typedef enum{
    ServerStatusOk,
    ServerStatusClientDisconnected,
}ServerStatus;

typedef struct{
    unsigned int port;
    unsigned int thread_count;
    const char *cert_file_path;
    const char *private_key_path;
    struct{
        bool (*invoke)(void *u_data, SSL_CTX *ctx);
        void *u_data;
    }ssl_ctx_callback;
    struct{
        void (*invoke)(void *u_data, const TlsServerClient client);
        void *u_data;
    }connect_callback;
    struct{
        void (*invoke)(void *u_data, void *u_client_data);
        void *u_data;
    }disconnect_callback;
    struct{
        void (*invoke)(void *u_data, void *u_client_data, uint8_t *received, size_t len);
        void *u_data;
    }receive_callback;
}TlsServerConfiguration;

TlsServerConfiguration tls_server_default_configuration(int port, const char *cert_file_path, const char *private_key_path);
TlsServer *tls_server_new(TlsServerConfiguration configuration);
void tls_server_free(TlsServer *server);
void tls_server_run(TlsServer *server);
void tls_server_request_stop(TlsServer *server);

ServerStatus tls_server_send(TlsServer *server, const TlsServerClient client, const uint8_t *buffer, size_t buffer_size);
ServerStatus tls_server_attach_client_data(TlsServer *server, const TlsServerClient client, void *u_client_data);
ServerStatus tls_server_enqueue_client_work(TlsServer *server, const TlsServerClient client, void (*work)(void *u_data), void *u_data);

#endif
