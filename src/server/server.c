#include "server/server.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include "http_core/http_core.h"
#include "openssl/ssl.h"
#include "assert.h"
#include "server_worker.h"
#include "config_manager.h"
#include "http2/http2.h"

ServerWorker *sworker;
typedef enum{
    Http2

}ClientType;

typedef struct{
    ClientType type;
    ClientHandle client;
    union{
        Http2Client *http2Client;
    };
}Client;

void signal_handler(int signal){}

bool send_cb(void *u_data, const uint8_t *data, size_t size){
    Client *client_data = (Client *)u_data;
    printf("Send cb %zu\n", client_data->client.index);
    server_worker_send(sworker, client_data->client, (char *)data, size);

    return true;
}

void on_disconnect(void *u_data, void *u_client_data, const ClientHandle client){
    Client *client_data = (Client *)u_client_data;
    http2_client_free(client_data->http2Client);
    free(client_data);
}

void on_connect(void *u_data, const ClientHandle client){
    Client *client_data = malloc(sizeof(Client));
    assert(client_data != NULL);
    Http2Client *http2Client = http2_client_new((Http2SendCb){.send = send_cb, .u_data = client_data});
    assert(http2Client != NULL);

    *client_data = (Client){
        .type = Http2,
        .client = client,
        .http2Client = http2Client
    };

    server_worker_attach_client_data(sworker, client, client_data);
}

void on_data(void *u, void *u_client_data, const ClientHandle client, char *buff, size_t len){
    Client *client_data = (Client *)u_client_data;
    http2_client_handle_message(client_data->http2Client, buff, len);
}

void error_handler(int signal){
    printf("Signal %d received. Ignoring...\n", signal);
}

int alpn_select_cb(SSL *ssl,
                   const unsigned char **out,
                   unsigned char *outlen,
                   const unsigned char *in,
                   unsigned int inlen,
                   void *arg) {

    static const unsigned char alpn_h2[] = { 
        2, 'h', '2',
        8, 'h','t','t','p','/','1', '.', '1'
    };

    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_h2, sizeof(alpn_h2), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

bool configure_ssl(void *data, SSL_CTX *ctx){
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    return true;
}

int server_run(){
    int status = 0;
    ConfigManager *manager = config_manager_load_from_appconfig();
    if(manager == NULL){
        fprintf(stderr, "Config Error: to load config file. Exiting...\n");
        return 1;
    }

    int port;
    const char *cert_path, *private_key_path, *cp;

    bool cert_status = config_manager_try_get_str(manager, "Certificate", &cert_path);
    bool key_status = config_manager_try_get_str(manager, "PrivateKey", &private_key_path);
    bool port_status = config_manager_try_get_int(manager, "Port", &port);
    bool content_path_status = config_manager_try_get_str(manager, "Content", &cp);

    if(!cert_status){
        fprintf(stderr, "Config Error: Unable to load 'Certificate'.\n");
    }
    if(!key_status){
        fprintf(stderr, "Config Error: Unable to load 'PrivateKey'.\n");
    }
    if(!port_status){
        fprintf(stderr, "Config Error: Unable to load 'Port'.\n");
    }
    if(!content_path_status){
        fprintf(stderr, "Config Error: Unable to load 'Content'.\n");
    }
    if(!cert_status || !key_status || !port_status || !content_path_status){
        fprintf(stderr, "Exiting...\n");
        status = 1;
        goto exit_manager;
    }

    if(!http_core_init(cp)){
        fprintf(stderr, "Unable to initialize http core\n");
        status = 1;
        goto exit_manager;
    }

    ServerWorkerConfig config = {
        .cert_file_path = cert_path,
        .private_key_path = private_key_path,
        .port = port
    };

    sworker = server_worker_new(config);
    assert(sworker != NULL);
    server_worker_set_receive_callback(sworker, on_data, NULL);
    server_worker_set_connect_callback(sworker, on_connect, NULL);
    server_worker_set_disconnect_callback(sworker, on_disconnect, NULL);
    server_worker_set_ssl_ctx_cb(sworker, configure_ssl, NULL);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    signal(SIGPIPE, error_handler);

    server_worker_run(sworker);
    server_worker_free(sworker);

exit_manager:
    config_manager_free(manager);
    return status;
}
