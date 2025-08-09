#ifndef SERVER_WORKER_H
#define SERVER_WORKER_H

#include <stddef.h>

typedef struct Client Client;

typedef enum{
    ServerWorkerStatusOk,
    ServerWorkerUnableToCreateSSLContext,
    ServerWorkerPortCreationError,
    ServerWorkerListenError,

    ServerWorkerClientDisconnected,
}ServerWorkerStatus;

typedef struct ServerWorker ServerWorker;

ServerWorker *server_worker_new();
void server_worker_free(ServerWorker *worker);

void server_worker_set_receive_callback(ServerWorker *worker, void (*callback)(void *u_data, const Client *client, char *received, size_t size), void *u_data);

ServerWorkerStatus server_worker_send(ServerWorker *worker, Client *client, char *buffer, size_t buffer_size);

void server_worker_request_stop(ServerWorker *worker);

#endif
