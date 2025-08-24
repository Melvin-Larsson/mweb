#include "http_core/http_core.h"
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include "io_uring/io_uring.h"

#define LOG_DEBUG_ENABLED
#define LOG_INFO(format, ...) printf("[HttpCore INFO] " format "\n", ##__VA_ARGS__)
#ifdef LOG_DEBUG_ENABLED
#define LOG_DEBUG(format, ...) printf("[HttpCore Debug] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) fprintf(stderr,"[HttpCore Error] " format "\n", ##__VA_ARGS__)
#define ERRNO_ERROR(format, ...) fprintf(stderr,"[HttpCore Error] " format "\n\t Reason: %s\n", strerror(errno), ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#define ERROR(format, ...)
#define ERRNO_ERROR(format, ...)
#endif

#define DEFAULT_INDEX_BUFFER_COUNT 32
#define ENTRY_COUNT_SCALING_FACTOR 1.5

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct{
    int index;
    const char *full_path;
}ContentHandle;

typedef struct{
    const char *path;
    ContentHandle content;
}IndexEntry;

typedef struct{
    IndexEntry *entries;
    size_t entry_buffer_size;
    size_t entry_count;
}Index;

typedef struct{
    Index index;
    size_t content_count;
}HttpCore;

static bool _load_content(HttpCore *core, const char *root, const char *path);
static void _print_index(Index *index);

bool _init_handle(HttpCore *core, ContentHandle *handle, const char *absolute_path);
void _clear_handle(ContentHandle *handle);

static bool _is_valid_content(const char *file_name);
static bool _has_file_extension(const char *file_name, const char *extension);
static size_t _concat_path(char *buffer, size_t buffer_size, const char *p1, const char *p2);

static bool _index_init(Index *index);
static bool _index_append(Index *index, IndexEntry entry);
static bool _index_try_get_content_handle(Index *index, const char *path, size_t path_length, ContentHandle *handle);


static HttpCore core;

bool http_core_init(const char *content_path){
    if(!_index_init(&core.index)){
        return false;
    }
    core.content_count = 0;

    if(!_load_content(&core, content_path, "/")){
        ERROR("Unable to load content index");
        return false;
    }

    _print_index(&core.index);

    return true;
}

typedef struct{
    ResponseCallback callback;
    HttpResponse result;
    int fd;
    CancellationToken *token;
    CancellationTokenCallbackHandle handle;
}ResponseCtx;

static off_t _file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        ERRNO_ERROR("Unable to read file size");
        return -1;
    }
    return st.st_size;
}

void _on_file_read(void *arg){
    ResponseCtx *ctx = (ResponseCtx *)arg;
    cancellation_token_remove_callback(ctx->token, ctx->handle);
    ctx->callback.invoke(ctx->callback.u_data, &ctx->result);
    free(ctx->result.body);
    free(ctx);
}

static void _free_response_ctx(void *arg){
    ResponseCtx *ctx = (ResponseCtx *)arg;
    free(ctx->result.body);
    free(ctx);
}

Task http_core_create_response_async(const HttpRequest *request, ResponseCallback callback, CancellationToken *token){
    if(callback.invoke == NULL){
        assert(false && "No callback function specified");
        return completed_task();
    }

    ContentHandle handle;
    if(!_index_try_get_content_handle(&core.index, request->path, request->path_length, &handle)){
        HttpResponse response = http_response_empty(HttpStatus404);
        callback.invoke(callback.u_data, &response);
        return completed_task();
    }

    int fd = open(handle.full_path, O_RDONLY);
    if(fd <= 0){
        ERROR("Indexed file not found");
        HttpResponse response = http_response_empty(HttpStatus404);
        callback.invoke(callback.u_data, &response);
        return completed_task();
    }

    off_t file_size = _file_size(handle.full_path);
    if(file_size < 0){
        return completed_task();
    }

    ResponseCtx *ctx = malloc(sizeof(ResponseCtx));
    if(ctx == NULL){
        ERROR("Unable to allocate response ctx");
        return completed_task();
    }
    *ctx = (ResponseCtx){
        .callback = callback,
        .fd = fd,
        .result = http_response_empty(HttpStatus200),
        .token = token
    };
    ctx->result.body_size = file_size;
    ctx->result.body = malloc(file_size);
    if(ctx->result.body == NULL){
        ERROR("Unable to allocate response body");
        free(ctx);
        return completed_task();
    }

    CancellationTokenCallback cb = {
        .on_cancel = _free_response_ctx,
        .u_data = ctx
    };
    cancellation_token_add_callback(token, cb, &ctx->handle);
    IoUringOp op = io_uring_read_op(fd, ctx->result.body, file_size);
    return io_uring_task(_on_file_read, ctx, op);
}

static bool _load_content(HttpCore *core, const char *root, const char *path){
    char full_root_path[512];
    size_t len = _concat_path(full_root_path, sizeof(full_root_path), root, path);
    
    if(len >= sizeof(full_root_path)){
        assert(false && "Buffer too small");
        return false;
    }

    DIR *root_dir = opendir(full_root_path);
    if(root_dir == NULL){
        ERROR("Unable to read directory %s", full_root_path);
        return false;
    }

    struct dirent *file;
    while((file = readdir(root_dir)) != NULL){
        if(file->d_name[0] == '.'){
            continue;
        }
        char relative_path[512];
        char full_path[512];

        size_t relative_path_size = _concat_path(relative_path, sizeof(relative_path), path, file->d_name);
        size_t full_path_size = _concat_path(full_path, sizeof(full_path), full_root_path, file->d_name);

        if(relative_path_size >= sizeof(relative_path) || full_path_size >= sizeof(full_path)){
            assert(false && "Buffer too small");
            goto exit_failure;
        }

        if(file->d_type == DT_REG){
            if(!_is_valid_content(file->d_name)){
                continue;
            }
            ContentHandle handle;
            if(!_init_handle(core, &handle, full_path)){
                goto exit_failure;
            }
            IndexEntry entry = {
                .content = handle,
                .path = strdup(relative_path)
            };
            if(entry.path == NULL || !_index_append(&core->index, entry)){
                _clear_handle(&handle);
                goto exit_failure;
            }
        }
        else if(file->d_type == DT_DIR){
            return _load_content(core, root, relative_path);
        }
    }    

    closedir(root_dir);
    return true;
exit_failure:
    closedir(root_dir);
    return false;
}

static void _print_index(Index *index){
    LOG_DEBUG("====Index===");
    for(size_t i = 0; i < index->entry_count; i++){
        IndexEntry entry = index->entries[i];
        LOG_DEBUG("%s: %d (%s)", entry.path, entry.content.index, entry.content.full_path);
    }
    LOG_DEBUG("");
}

bool _init_handle(HttpCore *core, ContentHandle *handle, const char *absolute_path){
    *handle = (ContentHandle){
        .full_path = strdup(absolute_path),
        .index = core->content_count++
    };

    return handle->full_path != NULL;
}

void _clear_handle(ContentHandle *handle){
    if(handle == NULL){
        return;
    }
    free(handle->full_path);
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

static bool _has_file_extension(const char *file_name, const char *extension){
    assert(file_name);
    assert(extension);

    char *ptr = strstr(file_name, extension);
    if(ptr != NULL && strlen(ptr) == strlen(extension)){
        return true;
    }
    return false;
}

static size_t _concat_path(char *buffer, size_t buffer_size, const char *p1, const char *p2){
    size_t p1_len = strlen(p1);
    size_t p2_len = strlen(p2);

    while(p1_len > 0 && p1[p1_len - 1] == '/'){
        p1_len--;
    }

    while(p2_len > 0 && p2[0] == '/'){
        p2_len--;
        p2++;
    }

    p1_len = min(buffer_size, p1_len);
    memcpy(buffer, p1, p1_len);
    if(p1_len == buffer_size){
        return p1_len;
    }
    buffer[p1_len] = '/';
    if(p1_len + 1== buffer_size){
        return p1_len + 1;
    }
    p2_len = min(buffer_size - p1_len - 1, p2_len);
    memcpy(buffer + p1_len + 1, p2, p2_len);

    if(p1_len + p2_len + 1 < buffer_size){
        buffer[p1_len + 1 + p2_len] = 0;
    }

    return p1_len + p2_len + 1;
}

static bool _index_init(Index *index){
    assert(index != NULL);
    *index = (Index){
        .entries = calloc(DEFAULT_INDEX_BUFFER_COUNT, sizeof(IndexEntry)),
        .entry_count = 0,
        .entry_buffer_size = DEFAULT_INDEX_BUFFER_COUNT
    };

    return index->entries != NULL;
}

static bool _index_append(Index *index, IndexEntry entry){
    if(index->entry_count == index->entry_buffer_size){
        size_t new_size = index->entry_buffer_size * ENTRY_COUNT_SCALING_FACTOR;
        assert(new_size > index->entry_buffer_size);
        IndexEntry *entries = calloc(new_size, sizeof(IndexEntry));
        if(entries == NULL){
            return false;
        }
        free(index->entries);
        index->entries = entries;
        index->entry_buffer_size = new_size;
    }

    index->entries[index->entry_count++] = entry;
    return true;
}

static bool _index_try_get_content_handle(Index *index, const char *path, size_t path_length, ContentHandle *handle){
    for(size_t i = 0; i < index->entry_count; i++){
        IndexEntry *entry = &index->entries[i];
        if(strlen(entry->path) == path_length && strncmp(entry->path, path, path_length) == 0){
            printf("Found for %s\n", entry->path);
            *handle = entry->content;
            return true;
        }
    }
    return false;
}

