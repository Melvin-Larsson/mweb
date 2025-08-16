#ifndef SERVER_WORKER_H
#define SERVER_WORKER_H

#include <openssl/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct{
    ssize_t index;
    uint64_t generation;
}ClientHandle;

typedef struct{
    const char *cert_file_path;
    const char *private_key_path;
    int port;
}ServerWorkerConfig;

typedef enum{
    ServerWorkerStatusOk,
    ServerWorkerUnableToCreateSSLContext,
    ServerWorkerPortCreationError,
    ServerWorkerListenError,

    ServerWorkerClientDisconnected,
}ServerWorkerStatus;

typedef struct ServerWorker ServerWorker;

ServerWorker *server_worker_new(ServerWorkerConfig config);
ServerWorkerStatus server_worker_run(ServerWorker *worker);
void server_worker_free(ServerWorker *worker);

void server_worker_set_ssl_ctx_cb(ServerWorker *worker, bool (*callback)(void *u_data, SSL_CTX *ctx ), void *u_data);

void server_worker_set_receive_callback(ServerWorker *worker, void (*callback)(void *u_data, void *u_client_data, const ClientHandle client, char *received, size_t size), void *u_data);
void server_worker_set_connect_callback(ServerWorker *worker, void (*callback)(void *u_data, const ClientHandle client), void *u_data);
void server_worker_set_disconnect_callback(ServerWorker *worker, void (*callback)(void *u_data, void * u_client_data, const ClientHandle client), void *u_data);

ServerWorkerStatus server_worker_attach_client_data(ServerWorker *worker, const ClientHandle client, void *u_client_data);

ServerWorkerStatus server_worker_send(ServerWorker *worker, ClientHandle client, char *buffer, size_t buffer_size);

void server_worker_request_stop(ServerWorker *worker);

#endif
