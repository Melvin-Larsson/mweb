#include "http_core/http_core.h"
#include "cJSON.h"
#include "stringbuilder.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef enum{
    HTML,
    CSS,
    Unknown,
}ContentType;


typedef struct{
    const char *name;
    const char *route;
    const char *page;
}Page;

typedef struct{
    Page *pages;
    size_t page_buffer_size; 
    size_t page_count; 
}Content;

typedef struct{
    const char *name;
    char *(*handle)(void);
}ContentFunction;

static char *_create_ok_response(const char *content, ContentType type);
static Page *_find_page(Content *content, const char *route, size_t route_length);
static bool _route_equals_ignoring_html(const char *r1, size_t l1, const char *r2, size_t l2);

static char *_populate_page(const char *content, Buffer *buffer, size_t *result_length);
static bool _try_get_content_function(char *key, size_t key_length, ContentFunction *result);
static char *_time_content();
static char *_served_count_content();

static bool _try_load_resources(Content **result);
static bool _load_content_from_dir(char *root_path, Content *result);

static bool _add_page_to_content_with_routes(Content *content, const char *page, const char *name);
static bool _add_page_to_content(Content *content, const char *page, const char *name, const char *route);


static bool _is_valid_content(const char *file_name);
static ContentType _get_content_type(const char *file_name);

static char *_load_content_file(const char *name);
static char *_read_file(const char *path);

static bool _has_file_extension(const char *file_name, const char *extension);
static char *_get_full_content_path(const char *relative_path);
static char *_concat_path(const char *path1, const  char *path2);

static ContentFunction functions[] = {
    {"TIME", _time_content },
    {"SERVED_COUNT", _served_count_content }
};
const size_t content_function_count = sizeof(functions) / sizeof(ContentFunction);

static int served_count = 0;
static char *_content_path;
static cJSON *routes_json = NULL;
static Content *content;


bool http_core_init(const char *content_path){
    _content_path = strdup(content_path);

    if(!_try_load_resources(&content)){
        goto exit_content_path;
    }

    char *routes_file_path = malloc(strlen(content_path) + strlen("/") + strlen("routes.json") + 1);
    strcpy(routes_file_path, content_path);
    strcat(routes_file_path, "/");
    strcat(routes_file_path, "routes.json");
    char *routes_content = _read_file(routes_file_path);
    free(routes_file_path);
    if(routes_content != NULL){
        printf("Parsing routes.json\n");
        routes_json = cJSON_Parse(routes_content);
        free(routes_content);

        if(routes_json == NULL){
            printf("Unable to parse routes.json\n");
        }
        else{
            printf("routes.json parsed\n");
        }
    }
    else{
        printf("Could not find routes.json\n");
    }

    return true;

exit_content_path:
    free(_content_path);
    return false;
}

void http_core_create_response(const HttpRequest *request, HttpResponse *response, Buffer *buffer){
    char response_400[] = "HTTP/1.1 400 Bad Request\r\n"
        "Connection: close\r\n\r\n";
    char *get = "GET ";

    if(request->method != GET){
        *response = http_response_empty(HttpStatus400);
        return;
    }

    printf("Received request for page %.*s\n", (int)request->path_length, request->path);
    served_count++;
    Page *page = _find_page(content, request->path, request->path_length);
    if(page == NULL){
        printf("404 not found\n");
        *response = http_response_empty(HttpStatus404);
        return;
    }

    ContentType type = _get_content_type(page->name);
    char *content_type;
    if(type == HTML){
       *response = http_response_empty(HttpStatus200);
       response->body = (uint8_t *)_populate_page(page->page, buffer, &response->body_size);
       content_type = "text/html; charset=UTF-8";

    }
    else if (type == CSS){
        *response = http_response_empty(HttpStatus200);
        response->body = (uint8_t *)page->page;
        response->body_size = strlen((char *)response->body);
        content_type = "text/css; charset=UTF-8";
    }
    else{
        printf("404 not found (unknown content type)\n");
        *response = http_response_empty(HttpStatus404);
        return;
    }

    uint8_t *ptr = buffer_get_append_ptr(buffer);
    buffer_snprintf(buffer, "%d", response->body_size);
    HttpHeaderField headers[] = {
         http_header_field_from_str("content-type", content_type),
         http_header_field_from_str("content-length", (char *)ptr),
    };
    HttpHeaderField *buffered_fields = (HttpHeaderField *)buffer_get_append_ptr(buffer);
    buffers_append(buffer, (uint8_t *)&headers, sizeof(headers));
 
    response->headers = buffered_fields;
    response->header_count = 2;
}

static char *_create_ok_response(const char *content, ContentType type){
    const char response_200_html[] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s";
    
    const char response_200_css[] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/css; charset=UTF-8\r\n"
        "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n"
        "Referrer-Policy: no-referrer-when-downgrade\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s";

    const char *response_template = type == CSS ? response_200_css : response_200_html;

    size_t max_str_len = strlen(response_template) + strlen(content) + 20;
    char *response = malloc(max_str_len + 1);
    int res =  snprintf(response, max_str_len, response_template, strlen(content), content);

    assert(res < max_str_len);

    return response;
}

static Page *_find_page(Content *content, const char *route, size_t route_length){
    if(strncmp(route, "/", route_length) == 0){
        route = "/index.html";
        route_length = strlen("/index.html");
    }

    for(size_t i = 0; i < content->page_count; i++){
        if(_route_equals_ignoring_html(content->pages[i].route, strlen(content->pages[i].route), route, route_length)){
            return &content->pages[i];
        }
    }

    return NULL;
}

static bool _route_equals_ignoring_html(const char *r1, size_t l1, const char *r2, size_t l2){
    printf("equals? %.*s == %.*s\n", (int)l1, r1, (int)l2, r2);
    size_t i = 0;
    for(; i < min(l1, l2); i++){
        if(r1[i] != r2[i]){
            break;
        }
    }

    if(i == l1 && i == l2){
        return true;
    }

    if(i == l1 && strncmp(&r2[i], ".html", l2 - i) == 0){
        return true;
    }

    if(i == l2 && strncmp(&r1[i], ".html", l1 - 1) == 0){
        return true;
    }

    return false;
}

static char *_populate_page(const char *content, Buffer *buffer, size_t *result_length){
    StringBuilder *string_builder = string_builder_new(strlen(content));

    const char *start = content;
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
        if(_try_get_content_function(tag_start + 1, tag_end - tag_start - 1, &function)){
            printf("get content\n\n");
            char *dynamic_content = function.handle();
            string_builder_append(string_builder, dynamic_content);
            free(dynamic_content);

        }
        start = tag_end + 1;
    }

    char *result_content = string_builder_to_string_and_free(string_builder);
    char *result = (char *)buffer_get_append_ptr(buffer);
   *result_length = buffers_append(buffer, (uint8_t *)result_content, strlen(result_content));
    free(result_content);
    return result;
}


static bool _try_get_content_function(char *key, size_t key_length, ContentFunction *result){
    for(size_t i = 0; i < content_function_count; i++){
        if(strncmp(key, functions[i].name, key_length) == 0){
            *result =  functions[i];
            return true;
        }
    }
    return false;
}


static bool _try_load_resources(Content **result){
    printf("Loading resources...\n");

    *result = malloc(sizeof(Content));
    **result = (Content){
        .pages = malloc(sizeof(Page) * 16),
        .page_buffer_size = 16,
        .page_count = 0
    };

    return _load_content_from_dir("/", *result);
}

static char *_time_content(){
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char *time = asctime(local_time);
    char *result = malloc(strlen(time) + 1);
    strcpy(result, time);
    result[strlen(result) - 1] = 0;
    return result;
}

static char *_served_count_content(){
    char *buff = malloc(8);
    snprintf(buff, sizeof(buff), "%d", served_count);
    return buff;
}



static bool _load_content_from_dir(char *root_path, Content *result){
#ifdef _DEFAULT_SOURCE

    printf("get full conetnt path for %s\n", root_path);
    char *full_root_path = _get_full_content_path(root_path);
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
            if(!_is_valid_content(file->d_name)){
                continue;
            }
            char *relative_path = _concat_path(root_path, file->d_name);
            printf("rel %s\n", relative_path);
            if(relative_path == NULL){
                break;
            }
            char *full_file_path = _get_full_content_path(relative_path);
            if(full_file_path == NULL){
                free(relative_path);
                break;
            }
            printf("Adding %s\n", full_file_path);
            char *content = _read_file(full_file_path);
            if(content == NULL){
                free(relative_path);
                free(full_file_path);
                break;
            }
            if(!_add_page_to_content_with_routes(result, content, relative_path)){
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
            char *relative_dir_path = _concat_path(root_path, file->d_name);
            bool status = _load_content_from_dir(relative_dir_path, result);
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

static bool _add_page_to_content_with_routes(Content *content, const char *page, const char *name){
    printf("Adding page '%s'\n", name);
    bool status = _add_page_to_content(content, page, name, name);
    if(routes_json == NULL){
        return status;
    }
    cJSON *routes = cJSON_GetObjectItemCaseSensitive(routes_json, name);
    if(routes == NULL){
        return status;
    }
    if(!cJSON_IsArray(routes)){
        fprintf(stderr, "Value for '%s' is not a valid array\n", name);
        return status;
    }
    cJSON *route;
    cJSON_ArrayForEach(route, routes)
    {
        if(!cJSON_IsString(route) || route->valuestring == NULL){
            fprintf(stderr, "Found invalid string in routes array for '%s'\n", name);
        }
        else{
            char *str = strdup(route->valuestring);
            printf("Routing '%s' to '%s'\n", str, name);
            status = status && _add_page_to_content(content, page, name, str);
        }
    }

    return status;
}


bool _add_page_to_content(Content *content, const char *page, const char *name, const char *route){
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
        .name = name,
        .route = route
    };
    content->page_count++;

    return true;
}


static char *_load_content_file(const char *name){
    assert(name);

    char *content_path = getenv("CONTENT_PATH");
    if(content_path == NULL){
        fprintf(stderr, "CONTENT_PATH environment variable is not set\n");
        return NULL;
    }

    char *path = malloc(strlen(content_path) + strlen(name) + 2);
    sprintf(path, "%s/%s", content_path, name);

    char *content = _read_file(path);
    free(path);
    return content;
}


static char *_read_file(const char *path){
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        fprintf(stderr, "Failed to open file '%s'\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *result = malloc(fsize + 1);
    size_t size = fread(result, fsize, 1, f);
    fclose(f);

    if(size == 0){
        fprintf(stderr, "Failed to read file '%s'\n", path);
        free(result);
        return NULL;
    }

    result[fsize] = 0;

    return result;
}

static bool _is_valid_content(const char *file_name){
    const char *valid_extensions[] = {".html", ".css"};
    const size_t valid_extensions_count = sizeof(valid_extensions) / sizeof(char *);

    for(size_t i = 0; i < valid_extensions_count; i++){
        if(_has_file_extension(file_name, valid_extensions[i])){
            return true;
        }
    }
    return false;
}

static ContentType _get_content_type(const char *file_name){
    if(_has_file_extension(file_name, ".css")){
        return CSS;
    }
    if(_has_file_extension(file_name, ".html")){
        return HTML;
    }
    return Unknown;
}

static bool _has_file_extension(const char *file_name, const char *extension){
    assert(file_name);
    assert(extension);

    char *ptr = strstr(file_name, extension);
    if(ptr != NULL && strlen(ptr) == strlen(extension)){
        return true;
    }
    return false;
}

static char *_get_full_content_path(const char *relative_path){
    assert(relative_path != NULL);

    return _concat_path(_content_path, relative_path);
}

static char *_concat_path(const char *path1, const char *path2){
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
