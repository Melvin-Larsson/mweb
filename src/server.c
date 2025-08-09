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
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "assert.h"
#include "server_worker.h"
#include "stringbuilder.h"
#include "dirent.h"
// #include "fcntl.h"

#define PORT 443
#define CONTENT_PATH_ENV_NAME "CONTENT_PATH"

typedef enum{
    HTML,
    CSS,
    Unknown,
}ContentType;

// typedef struct{
//     SSL *ssl;
//     int socketfd;
// }Client;

static int served_count = 0;

typedef struct{
    char *name;
    char *page;
}Page;

typedef struct{
    Page *pages;
    size_t page_buffer_size; 
    size_t page_count; 
}Content;

char *load_file(const char *path){
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        fprintf(stderr, "Failed to open file '%s'", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *result = malloc(fsize + 1);
    size_t size = fread(result, fsize, 1, f);
    fclose(f);

    if(size == 0){
        fprintf(stderr, "Failed to read file '%s'", path);
        free(result);
        return NULL;
    }

    result[fsize] = 0;

    return result;
}

char *load_content_file(char *name){
    assert(name);

    char *content_path = getenv("CONTENT_PATH");
    if(content_path == NULL){
        fprintf(stderr, "CONTENT_PATH environment variable is not set\n");
        return NULL;
    }

    char *path = malloc(strlen(content_path) + strlen(name) + 2);
    sprintf(path, "%s/%s", content_path, name);

    char *content = load_file(path);
    free(path);
    return content;
}

bool add_page_to_content(Content *content, char *page, char *name){
    if(content->page_count == content->page_buffer_size){
        size_t new_page_buffer_size = content->page_buffer_size * 3 / 2;
        Page *new_page_buffer = realloc(content->pages, new_page_buffer_size); 
        if(new_page_buffer == NULL){
            return false;
        }
        content->pages = new_page_buffer;
        content->page_buffer_size = new_page_buffer_size;
    }

    content->pages[content->page_count] = (Page){
        .page = page,
        .name = name
    };
    content->page_count++;

    return true;
}

char *create_ok_response(char *content, ContentType type){
    const char response_200_html[] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s";
    
    const char response_200_css[] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/css; charset=UTF-8\r\n"
        "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s";

    char *response_template = type == CSS ? response_200_css : response_200_html;

    size_t max_str_len = strlen(response_template) + strlen(content) + 20;
    char *response = malloc(max_str_len + 1);
    int res =  snprintf(response, max_str_len, response_template, strlen(content), content);

    assert(res < max_str_len);

    return response;
}

char *concat_path(char *path1, char *path2){
    assert(path1 != NULL);
    assert(path2 != NULL);

    char *result = malloc(strlen(path1) + strlen(path2) + 2);
    if(result == NULL){
        return NULL;
    }
    if(path1[strlen(path1) - 1] == '/' || path2[0] == '/' || strlen(path1) == 0 || strlen(path2) == 0){
        sprintf(result, "%s%s", path1, path2);
    }
    else{
        sprintf(result, "%s/%s", path1, path2);
    }
    return result;
}


char *get_full_content_path(char *relative_path){
    assert(relative_path != NULL);

    char *content_path = getenv(CONTENT_PATH_ENV_NAME);
    if(content_path == NULL){
        return NULL;
    }
    return concat_path(content_path, relative_path);
}

bool has_file_extension(const char *file_name, const char *extension){
    assert(file_name);
    assert(extension);

    char *ptr = strstr(file_name, extension);
    if(ptr != NULL && strlen(ptr) == strlen(extension)){
        return true;
    }
    return false;
}

bool is_valid_content(char *file_name){
    const char *valid_extensions[] = {".html", ".css"};
    const size_t valid_extensions_count = sizeof(valid_extensions) / sizeof(char *);

    for(size_t i = 0; i < valid_extensions_count; i++){
        if(has_file_extension(file_name, valid_extensions[i])){
            return true;
        }
    }
    return false;
}


ContentType get_content_type(char *file_name){
    if(has_file_extension(file_name, ".css")){
        return CSS;
    }
    if(has_file_extension(file_name, ".html")){
        return HTML;
    }
    return Unknown;
}


bool load_content_from_dir(char *root_path, Content *result){
#ifdef _DEFAULT_SOURCE

    printf("get full conetnt path for %s\n", root_path);
    char *full_root_path = get_full_content_path(root_path);
    if(full_root_path == NULL){
        return false;
    }
    printf("Opening directory %s\n", full_root_path);

    DIR *root_dir = opendir(full_root_path);
    if(root_dir == NULL){
        fprintf(stderr, "Unable to read directory %s\n", full_root_path);
        return false;
    }

    struct dirent *file;
    while((file = readdir(root_dir)) != NULL){
        if(file->d_name[0] == '.'){
            continue;
        }
        if(file->d_type == DT_REG){
            printf("Found file %s\n", file->d_name);
            if(!is_valid_content(file->d_name)){
                continue;
            }
            char *relative_path = concat_path(root_path, file->d_name);
            printf("rel %s\n", relative_path);
            if(relative_path == NULL){
                break;
            }
            char *full_file_path = get_full_content_path(relative_path);
            if(full_file_path == NULL){
                free(relative_path);
                break;
            }
            printf("Adding %s\n", full_file_path);
            char *content = load_file(full_file_path);
            if(content == NULL){
                free(relative_path);
                free(full_file_path);
                break;
            }
            if(!add_page_to_content(result, content, relative_path)){
                free(relative_path);
                free(full_file_path);
                free(content);
                break;
            }

            printf("Page %s added with content %s\n", relative_path, content);
            free(full_file_path);
        }
        else if(file->d_type == DT_DIR){
            printf("Found dir %s\n", file->d_name);
            char *relative_dir_path = concat_path(root_path, file->d_name);
            bool status = load_content_from_dir(relative_dir_path, result);
            free(relative_dir_path);
            return status;
        }
    }

    free(full_root_path);
    closedir(root_dir);
    return true;
#else
    return false;
#endif

}

bool try_load_resources(Content **result){
    printf("Loading resources...\n");

    *result = malloc(sizeof(Content));
    **result = (Content){
        .pages = malloc(sizeof(Page) * 16),
        .page_buffer_size = 16,
        .page_count = 0
    };

    return load_content_from_dir("/", *result);
}

SSL_CTX *create_ssl_context(){
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if(ctx == NULL){
        perror("Unalbe to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    char *cert_file = getenv("CERT_FILE_PATH");
    char *private_key_file = getenv("PRIVATE_KEY_FILE_PATH");

    if(cert_file == NULL){
        fprintf(stderr, "CERT_FILE_PATH environment variable is not set\n");
        exit(EXIT_FAILURE);
    }
    if(private_key_file == NULL){
        fprintf(stderr, "PRIVATE_KEY_FILE_PATH environment variable is not set\n");
        exit(EXIT_FAILURE);
    }

    printf("Using files, cert: %s, private key: %s\n", cert_file, private_key_file);

    if(SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384")){

        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_set_ciphersuites(ctx,
                "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")){

        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(!SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1)){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("SSL Context created\n");
    
    return ctx;
}

char *time_content(){
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char *time = asctime(local_time);
    char *result = malloc(strlen(time) + 1);
    strcpy(result, time);
    result[strlen(result) - 1] = 0;
    return result;
}

char *served_count_content(){
    char *buff = malloc(8);
    snprintf(buff, sizeof(buff), "%d", served_count);
    return buff;
}

typedef struct{
    const char *name;
    char *(*handle)(void);
}ContentFunction;

static ContentFunction functions[] = {
    {"TIME", time_content },
    {"SERVED_COUNT", served_count_content }
};
const size_t content_function_count = sizeof(functions) / sizeof(ContentFunction);

bool try_get_content_function(char *key, size_t key_length, ContentFunction *result){
    for(size_t i = 0; i < content_function_count; i++){
        if(strncmp(key, functions[i].name, key_length) == 0){
            *result =  functions[i];
            return true;
        }
    }
    return false;
}

char *populate_page(char *content){
    StringBuilder *string_builder = string_builder_new(strlen(content));

    char *start = content;
    while(*start != '\0'){
        char *tag_start = strstr(start, "[");
        if(tag_start == NULL){
            string_builder_append(string_builder, start);
            break;
        }
        char *tag_end = strstr(tag_start, "]");
        if(tag_end == NULL){
            string_builder_append(string_builder, start);
            break;
        }

        string_builder_append_len(string_builder, start, tag_start - start);

        if(*(tag_start + 1) == '['){
            string_builder_append(string_builder, "[");
            start = tag_start + 2;
            continue;
        }

        ContentFunction function;
        if(try_get_content_function(tag_start + 1, tag_end - tag_start - 1, &function)){
            printf("get content\n\n");
            char *dynamic_content = function.handle();
            string_builder_append(string_builder, dynamic_content);
            free(dynamic_content);

        }
        start = tag_end + 1;
    }

    return string_builder_to_string_and_free(string_builder);
}

Page *find_page(Content *content, char *name){
    if(strcmp(name, "/") == 0){
        name = "/index.html";
    }

    for(size_t i = 0; i < content->page_count; i++){
        if(strcmp(content->pages[i].name, name) == 0 || strncmp(content->pages[i].name, name, strlen(content->pages[i].name) - strlen(".html")) == 0){
            return &content->pages[i];
        }
    }

    return NULL;
}

ServerWorker *sworker;
void signal_handler(int signal){
//     assert(sworker);
//     server_worker_request_stop(sworker);
}

Content *content;
void on_data(void *u, const Client *client, char *buff, size_t len){
   printf("Received: '%.*s'\n", (int)len, buff); 

    char response_404[] = "HTTP/1.1 404 Not Found\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Content-Length: 0\n\n";
   char *get = "GET ";

   if(strncmp(buff, get, strlen(get)) != 0){
       printf("no GET\n");
       exit(EXIT_FAILURE);
       return;
   }
   char *requested_content = buff + strlen(get);
   char *ptr = requested_content;
   while(*ptr && *ptr != ' '){
       ptr++;
   }
   if(!*ptr){
       printf("bad request\n");
       exit(EXIT_FAILURE);
       return;
   }
   *ptr = '\0';

   printf("Received request for page '%s'\n", requested_content);
   Page *page = find_page(content, requested_content);
   if(page != NULL){
       ContentType type = get_content_type(page->name);
       if(type == HTML){
           char *page_content = populate_page(page->page);
           char *response = create_ok_response(page_content, type);


           server_worker_send(sworker, client, response, strlen(response));

           free(page_content);
           free(response);
       }
       else{
           char *response = create_ok_response(page->page, type);
           server_worker_send(sworker, client, response, strlen(response));
           free(response);
       }
   }
   else{
       printf("404 not found\n");
       server_worker_send(sworker, client, response_404, strlen(response_404));
   }
}

int server_run(){
    if(!try_load_resources(&content)){
        exit(EXIT_FAILURE);
    }

    sworker = server_worker_new();
    assert(sworker != NULL);
    server_worker_set_receive_callback(sworker, on_data, NULL);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    server_worker_run(sworker);

    return 0;


//     int sockfd = socket(AF_INET, SOCK_STREAM, 0);
//     if(sockfd < 0){
//         perror("Socket fail");
//         exit(EXIT_FAILURE);
//     }

//     int opt = 1;
//     if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0){
//         perror("Failed to set socket options");
//         exit(EXIT_FAILURE);
//     }

//     if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
//         perror("Failed to set socket options");
//         exit(EXIT_FAILURE);
//     }

//     struct sockaddr_in address;
//     socklen_t addrlen = sizeof(address);
//     address.sin_family = AF_INET;
//     address.sin_port = htons(PORT);
//     address.sin_addr.s_addr = INADDR_ANY;

//     if(bind(sockfd, (struct sockaddr *)&address, addrlen) < 0){
//         perror("Bind failed");
//         exit(EXIT_FAILURE);
//     }

//     if(listen(sockfd, 3) < 0){
//         perror("Listen");
//         exit(EXIT_FAILURE);
//     }

//     SSL_CTX *ctx = create_ssl_context();
//     if(ctx == NULL){
//         exit(EXIT_FAILURE);
//     }

//     char response_404[] = "HTTP/1.1 404 Not Found\n"
//         "Content-Type: text/html; charset=UTF-8\n"
//         "Content-Length: 0\n\n";

//     int epollfd = epoll_create1(0);
//     if(epollfd < 0){
//         perror("Failed creating epoll");
//         exit(EXIT_FAILURE);
//     }

//     struct epoll_event socket_cfg = {
//         .events = EPOLLIN,
//         .data.fd = sockfd
//     };
//     if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &socket_cfg) < 0){
//         perror("Failed to listen");
//         exit(EXIT_FAILURE);
//     }

//     printf("Listening on port %d...\n", PORT);

//     struct epoll_event events[16];
//     int client_count = 0;
//     while(true){
//         int epoll_result = epoll_wait(epollfd, events, sizeof(events)/sizeof(struct epoll_event), -1);
//         if(epoll_result == -1){
//             perror("Wait failed");
//             exit(EXIT_FAILURE);
//         }else if(epoll_result == 0){
//             printf("what?\n");
//             continue;
//         }

//         for(int i = 0; i < epoll_result; i++){
//             if(events[i].data.fd == sockfd){
//                 struct sockaddr_storage sockaddr;
//                 socklen_t addrlen = sizeof(sockaddr);
//                 int clientfd = accept(sockfd, (struct sockaddr *)&sockaddr, &addrlen);
//                 if(clientfd < 0){
//                     perror("Accept error");
//                     continue;
//                 }

//                 if(sockaddr.ss_family == AF_INET){
//                     struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)&sockaddr;
//                     uint8_t *addr = (uint8_t *)&sockaddr_ipv4->sin_addr.s_addr;
//                     printf("Client of adddress %d.%d.%d.%d connected\n", addr[0], addr[1], addr[2], addr[3]);
//                 }
//                 else if(sockaddr.ss_family == AF_INET6){
//                     struct sockaddr_in6 *sockaddr_ipv6 = (struct sockaddr_in6 *)&sockaddr;
//                     printf("Client of adddress ");
//                     uint8_t *addr = (uint8_t *)&sockaddr_ipv6->sin6_addr;
//                     for(size_t i = 0; i < 16; i += 2){
//                         printf("%X%X", addr[i], addr[i + 1]);
//                         if(i < 14){
//                             printf(":");
//                         }
//                     }
//                     printf(" Connected\n");
//                 }
//                 else{
//                     printf("Unknown address type %d connected\n", sockaddr.ss_family);
//                 }
// //                 int flags = fcntl(clientfd, F_GETFL, 0);
// //                 fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

//                 printf("New ssl\n");
//                 SSL *ssl = SSL_new(ctx);
//                 if(SSL_set_fd(ssl, clientfd) != 1){
//                     ERR_print_errors_fp(stderr);
//                     SSL_free(ssl);
//                     close(clientfd);
//                     continue;
//                 }

//                 printf("Accept client ssl\n");
//                 if(!SSL_accept(ssl)){
//                 printf("Accept client ssl nooo\n");
//                     fprintf(stderr, "Unable to accept client\n");
//                     close(clientfd);
//                     SSL_free(ssl);
//                 }

//                 printf("Allocate client space\n");
//                 Client *client = malloc(sizeof(Client));
//                 if(client == NULL){
//                     fprintf(stderr, "Unable to malloc client\n");
//                     close(clientfd);
//                     SSL_free(ssl);
//                 }
//                 *client = (Client){
//                     .socketfd = clientfd,
//                     .ssl = ssl,
//                 };

//                 struct epoll_event new_event = {
//                     .events = EPOLLIN | EPOLLOUT | EPOLLET,
//                     .data.ptr = client
//                 };
//                 printf("Add clien to epoll\n");
//                 if(epoll_ctl(epollfd, EPOLL_CTL_ADD, clientfd, &new_event) < 0){
//                     perror("Failed to epoll connection");
//                     close(clientfd);
//                     free(client);
//                     SSL_free(ssl);
//                     continue;
//                 }

//                 client_count++;
//                 setenv("TZ", "Europe/Stockholm", 1);
//                 time_t now = time(NULL);
//                 struct tm *local_time = localtime(&now);
//                 char *time = asctime(local_time);
//                 printf("Acceted client. %d clients connected at %s\n", client_count, asctime(local_time));
//             }
//             else{
//                 Client *client = (Client *)events[i].data.ptr;

//                 char buff[1024];
//                 int size = SSL_read(client->ssl, buff, sizeof(buff) - 1);
//                 if(size < 0){
//                     goto disconnect;
//                 }

//                 buff[1023] = 0;

//                 served_count++;

// disconnect:
//                 epoll_ctl(epollfd, EPOLL_CTL_DEL, client->socketfd, NULL);
//                 SSL_shutdown(client->ssl);
//                 SSL_free(client->ssl);
//                 close(client->socketfd);
//                 free(client);

//                 client_count--;
//                 printf("Client disconnect. %d clients connected\n", client_count);
//             }
//         }    
//     }

// exit:
//     close(epollfd);
//     close(sockfd);
//     SSL_CTX_free(ctx);

//     for(size_t i = 0; i < content->page_count; i++){
//         Page *page = &content->pages[i];
//         free(page->page);
//         free(page->name);
//     }
//     free(content);

//     return 0;
}
