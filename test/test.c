#include <errno.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "stdbool.h"
#include "sys/socket.h"
#include "netdb.h"
#include "unistd.h"
#include "assert.h"

// #define LOG_DEBUG_ENABLED

#define LOG_INFO(format, ...) printf("[INFO] " format "\n", ##__VA_ARGS__)

#ifdef LOG_DEBUG_ENABLED
    static int _ssl_error_cb(const char *str, size_t len, void *u){
        fprintf(stderr, "[SSL Error] %s\n", str);
        return 1;
    }

#define LOG_DEBUG(format, ...) printf("[Debug] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) fprintf(stderr,"[Error] " format "\n", ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) fprintf(stderr,"[Error] " format "\n\t Reason: %s\n", strerror(errno), ##__VA_ARGS__)
#define SSL_ERROR(format, ...) fprintf(stderr,"[Error] " format "\n", ##__VA_ARGS__); ERR_print_errors_cb(_ssl_error_cb, NULL)
#else
#define LOG_DEBUG(format, ...)
#define ERROR(format, ...)
#define SSL_ERROR(format, ...)
#define ERRNO_ERROR(format, ...)
#endif


typedef struct{
    int socket;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;

    char *data_buffer;
    size_t size;

    bool stop;
}Client;

static SSL_CTX *_create_ssl_ctx();
static Client *_create_client(SSL_CTX *ctx, char *hostname);

static bool _client_write(Client *client, char *data, size_t length);
static size_t _client_read(Client *client, char *data, size_t length);
static bool _client_connect(Client *client);
static bool _client_disconnect(Client *client);
static int _handle_request(Client *client, int (*handle)(Client *client), int error_thresh);
static void *run(void *arg);

#define CLIENT_COUNT 1
SSL_CTX *ctx;
Client *clients[CLIENT_COUNT];

int main(){
    printf("Hello World!\n");

    ctx = _create_ssl_ctx();
    if(ctx == NULL){
        return 1;
    }

    pthread_t threads[CLIENT_COUNT];
    for(size_t i = 0; i < CLIENT_COUNT; i++){
        clients[i] = _create_client(ctx, "localhost");
        if(clients[i] == NULL){
            ERROR("Unable to create client #%zu ", i);
            return -1;
        }
        pthread_create(&threads[i], NULL, run, clients[i]);
    }

    size_t count = 1000;
    while(count > 0){
        bool done = true;
        for(size_t i = 0; i < CLIENT_COUNT; i++){
            done = done && clients[i]->stop;
        }
        if(done){
            break;
        }
        count--;
        sleep(1);
    }

    for(size_t i = 0; i < CLIENT_COUNT; i++){
        clients[i]->stop = true;
    }

    LOG_INFO("Joining threads");
    size_t fail_count = 0;
    for(size_t i = 0; i < CLIENT_COUNT; i++){
        void *res;
        pthread_join(threads[i], &res);
        if((uintptr_t)res == 0){
            fail_count++;
        }
    }

    LOG_INFO("%zu threads failed", fail_count);
}

static void *run(void *arg){
    Client *client = (Client*)arg;
    char send[] = "GET / HTTP/1.1";
    char buff[1024];

    LOG_INFO("Connect");
    if(!_client_connect(client)){
        ERROR("Failed to connect");
        return NULL;
    }
    LOG_DEBUG("Write");
    if(!_client_write(client, send, sizeof(send))){
        ERROR("Failed to write");
        return NULL;
    }
    LOG_DEBUG("Read");
    int l = sizeof(buff);
    while(l == sizeof(buff)){
        l = _client_read(client, buff, sizeof(buff) - 1);
        buff[l] = 0;
        LOG_DEBUG("Read %d bytes %s", l, buff);
        if(l <= 0){
            ERROR("Failed to read");
            return NULL;
        }
    }
    LOG_DEBUG("Disconnect");
    if(!_client_disconnect(client)){
        ERROR("Failed to disconnect");
        return NULL;
    }

    client->stop = true;

    return (void *)1;
}

static int _client_write_f(Client *client){
    return SSL_write(client->ssl, client->data_buffer, client->size);
}
static int _client_read_f(Client *client){
    return SSL_read(client->ssl, client->data_buffer, client->size);
}
static int _client_connect_f(Client *client){
    return SSL_connect(client->ssl);
}
static int _client_disconnect_f(Client *client){
    return SSL_shutdown(client->ssl);
}

static bool _client_write(Client *client, char *data, size_t length){
    client->data_buffer = data;
    client->size = length;
    return _handle_request(client, _client_write_f, 0) > 0;
}
static size_t _client_read(Client *client, char *data, size_t length){
    client->data_buffer = data;
    client->size = length;
    return _handle_request(client, _client_read_f, 0);
}
static bool _client_connect(Client *client){
    return _handle_request(client, _client_connect_f, 0) > 0;
}
static bool _client_disconnect(Client *client){
    return _handle_request(client, _client_disconnect_f, -1) >= 0;
}

static bool _is_bio_empty(Client *client){
    char buff[1024];
    int len1 = BIO_read(client->wbio, buff, sizeof(buff));
    int len2 = BIO_read(client->rbio, buff, sizeof(buff));
    return (len1 == 0 || len1 == -1) && (len2 == 0 || len2 == -1);
}

static int _handle_request(Client *client, int (*handle)(Client *client), int error_thresh){
    assert(_is_bio_empty(client));

    while(!client->stop){
        int ret = handle(client);
        int reason = SSL_get_error(client->ssl, ret);
        char buff[1024];
        int len = BIO_read(client->wbio, buff, sizeof(buff));
        if(len > 0){
                write(client->socket, buff, len);
//             char *ptr = buff;
//             size_t write_size = 31;
//             while(len > 0){
//                 size_t l = write_size > len ? write_size : len;
//                 write(client->socket, ptr, l);
//                 ptr += l;
//                 len -= l;
//                 usleep(100 * 1000);
//             }
            LOG_INFO("%zu bytes written to socket", len);
        }
        if(ret <= error_thresh){
            ERROR("Reason %d: %s", reason, ERR_reason_error_string(ERR_get_error()));

            if(reason == SSL_ERROR_WANT_READ){
                LOG_INFO("Want read");
                char buff[1024];
                size_t len = read(client->socket, buff, sizeof(buff));
                LOG_INFO("Data read");
                BIO_write(client->rbio, buff, len);
            }
            else if(reason == SSL_ERROR_WANT_WRITE){
                LOG_INFO("Want write");
            }
            else{
                ERROR("Fail 1");
                return -1;
            }
        }
        else{
            LOG_INFO("Return good ret %d\n", ret);
            return ret;
        }
    }

    ERROR("Fail 2");
    return -1;
}

static Client *_create_client(SSL_CTX *ctx, char *hostname){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1){
        ERRNO_ERROR("Unable to create socket");
        return NULL;
    }

    struct hostent *server = gethostbyname(hostname);

    if(server == NULL){
        ERROR("Unable to resolve hostname\n");
        goto error_sock;
    }

    struct sockaddr_in serveraddr = {
        .sin_family = server->h_addrtype,
        .sin_port = htons(6969)
    };
    memcpy(&serveraddr.sin_addr.s_addr, server->h_addr, server->h_length);

    if(connect(sock, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == -1){
        ERRNO_ERROR("Unable to connect to server");
        goto error_sock;
    }

    char *buffer = malloc(1024);
    if(buffer == NULL){
        ERROR("Unable to allocate buffer");
        goto error_sock;
    }

    SSL *ssl = SSL_new(ctx);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if(ssl == NULL || rbio == NULL){
        SSL_ERROR("Unable to allocate ssl structures");
        goto error_ssl;
    }

    SSL_set_bio(ssl, rbio, wbio);

    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        SSL_ERROR("Failed to set the SNI hostname\n");
        goto error_ssl;
    }

    if (!SSL_set1_host(ssl, hostname)) {
        SSL_ERROR("Failed to set the certificate verification hostname");
        goto error_ssl;
    }

    Client *result = malloc(sizeof(Client));
    if(result == NULL){
        ERROR("Unable to allocate client");
        goto error_ssl;
    }

    *result = (Client){
        .rbio = rbio,
        .wbio = wbio,
        .socket = sock,
        .ssl = ssl,
        .stop = false,
    };
    
    return result;

error_ssl:
    SSL_free(ssl);
    BIO_free(rbio);
    BIO_free(wbio);
error_buff:
    free(buffer);
error_sock:
    close(sock);
    return NULL;
}

static SSL_CTX *_create_ssl_ctx(){
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERROR("Failed to create the SSL_CTX\n");
        goto error;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        ERROR("Failed to set the default trusted certificate store\n");
        goto error;
    }
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        ERROR("Failed to set the minimum TLS protocol version\n");
        goto error;
    }

    return ctx;

error:
    SSL_CTX_free(ctx);
    return NULL;
}
