#include "server.h"
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
#include "cJSON.h"
#include "http_core/http_core.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "assert.h"
#include "server_worker.h"
#include "stringbuilder.h"
#include "dirent.h"
#include "config_manager.h"
#include "http2/http2.h"
// #include "fcntl.h"

// typedef struct{
//     SSL *ssl;
//     int socketfd;
// }Client;
//


ServerWorker *sworker;
void signal_handler(int signal){
//     assert(sworker);
//     server_worker_request_stop(sworker);
}

Http2Ctx *ctx;
void on_disconnect(void *u_data, void *u_client_data, const ClientHandle client){
   http2_handle_disconnect(ctx, u_client_data, client);
}

void on_connect(void *u_data, const ClientHandle client){
   http2_handle_connect(ctx, client);
}

void on_data(void *u, void *client_data, const ClientHandle client, char *buff, size_t len){
   http2_handle_message(ctx, client_data, client, buff, len);
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

   ctx = http2_new_ctx(sworker);
   if(ctx == NULL){
       return 1;
   }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    signal(SIGPIPE, error_handler);

    server_worker_run(sworker);
    server_worker_free(sworker);

exit_manager:
    config_manager_free(manager);
    return status;
}
