#include "http_core/http_core.h"
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "io_uring/io_uring.h"

#define LOG_CONTEXT "HttpCore"
#include "logging.h"

#define DEFAULT_INDEX_BUFFER_COUNT 32
#define ENTRY_COUNT_SCALING_FACTOR 1.5

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef enum{
    HTML,
    CSS,
    M3U8,
    TS,
    Unknown,
    MP4
}ContentType;

typedef struct{
    int index;
    const char *full_path;
    ContentType type;
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
static ContentType _get_content_type(const char *file_name);
static bool _has_file_extension(const char *file_name, const char *extension);
static size_t _concat_path(char *buffer, size_t buffer_size, const char *p1, const char *p2);

static bool _index_init(Index *index);
static void _index_clear(Index *index);
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

void http_core_free(){
    _index_clear(&core.index);
}

typedef struct{
    ResponseCallback callback;
    HttpResponse result;
    Buffer header_buffer;
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
    LOG_INFO("File read, handling response");
    ResponseCtx *ctx = (ResponseCtx *)arg;
    cancellation_token_remove_callback(ctx->token, ctx->handle);
    ctx->callback.invoke(ctx->callback.u_data, &ctx->result);

    free(ctx->result.body);
    free(ctx->header_buffer.data);
    close(ctx->fd);
    free(ctx);
    LOG_DEBUG("Response handled");
}

static void _free_response_ctx(void *arg){
    ResponseCtx *ctx = (ResponseCtx *)arg;
    free(ctx->header_buffer.data);
    free(ctx);
}

Task http_core_create_response_async(const HttpRequest *request, ResponseCallback callback, CancellationToken *token){
    if(callback.invoke == NULL){
        assert(false && "No callback function specified");
        return completed_task();
    }

    LOG_TRACE("Creating response for %.*s", request->path_length, request->path);

    ContentHandle handle;
    if(!_index_try_get_content_handle(&core.index, request->path, request->path_length, &handle)){
        LOG_DEBUG("404 file '%.*s' not found", request->path_length, request->path);
        HttpResponse response = http_response_empty(HttpStatus404);
        callback.invoke(callback.u_data, &response);
        return completed_task();
    }

    LOG_TRACE("Content found");

    int fd = open(handle.full_path, O_RDONLY);
    if(fd <= 0){
        ERRNO_ERROR("Unable to open file");
        HttpResponse response = http_response_empty(HttpStatus404);
        callback.invoke(callback.u_data, &response);
        return completed_task();
    }

    off_t file_size = _file_size(handle.full_path);
    if(file_size < 0){
        return completed_task();
    }

    LOG_TRACE("Creating response headers");
    HttpHeaderField fields[2];
    char buff[32];
    size_t count = 0;
    if(handle.type == M3U8){
        fields[count++] = http_header_field_from_str("content-type", "application/vnd.apple.mpegurl");
    }
    else if(handle.type == TS){
        fields[count++] = http_header_field_from_str("content-type", "video/mp2t");
        snprintf(buff, sizeof(buff), "%zu", file_size);
        fields[count++] = http_header_field_from_str("content-length", buff);
    }

    size_t header_data_size = sizeof(HttpHeaderField) * (count + 1) + http_header_fields_get_length(fields, count);
    uint8_t *header_data = malloc(header_data_size);
    if(header_data == NULL){
        ERROR("Unable to allocate header buffer");
        return completed_task();
    }

    Buffer header_buffer;
    buffers_init_buffer(&header_buffer, header_data, header_data_size);
    HttpResponse response = http_response_empty(HttpStatus200);
    LOG_TRACE("Moving header fields to buffer");
    response.headers = http_header_fields_to_buffer(fields, count, &header_buffer);
    assert(header_buffer.used_size < header_buffer.total_size);
    LOG_TRACE("Moved header fields to buffer");

    response.header_count = count;
    response.body_size = file_size;
    response.body = malloc(file_size);

    if(response.body == NULL){
        ERROR("Unable to allocate response body");
        free(header_data);
        return completed_task();
    }

    ResponseCtx *ctx = malloc(sizeof(ResponseCtx));
    if(ctx == NULL){
        ERROR("Unable to allocate response ctx");
        free(response.body);
        free(header_data);
        return completed_task();
    }
    *ctx = (ResponseCtx){
        .callback = callback,
        .fd = fd,
        .result = response,
        .token = token,
        .header_buffer = header_buffer
    };

    LOG_DEBUG("Enqueing work to load %.*s", (int)request->path_length, request->path);
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
        LOG_TRACE("Loading file '%s'", file->d_name);
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
            if(!_load_content(core, root, relative_path)){
                goto exit_failure;
            }
        }
    }    

    closedir(root_dir);
    return true;
exit_failure:
    ERROR("Unable to load content");
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
        .index = core->content_count++,
        .type = _get_content_type(absolute_path)
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
    return _get_content_type(file_name) != Unknown;
}

static ContentType _get_content_type(const char *file_name){
    const char *extension = strstr(file_name, ".");
    while(strstr(extension, ".") != NULL){
        extension = strstr(extension, ".") + 1;
    }
    LOG_TRACE("Extension '%s'", extension);
    if(strcmp(extension, "html") == 0){
        return HTML;
    }
    else if(strcmp(extension, "css") == 0){
        return CSS;
    }
    else if(strcmp(extension, "m3u8") == 0){
        return M3U8;
    }
    else if(strcmp(extension, "ts") == 0){
        return TS;
    }
    else if(strcmp(extension, "mp4") == 0){
        return MP4;
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

static void _index_clear(Index *index){
    if(index == NULL){
        return;
    }

    for(size_t i = 0; i < index->entry_count; i++){
        IndexEntry *entry = &index->entries[i];
        free((char *)entry->path);
        free((char *)entry->content.full_path);
        entry->path = NULL;
        entry->content.full_path = NULL;
    }

    free(index->entries);
    *index = (Index){
        .entries = NULL,
        .entry_buffer_size = 0,
        .entry_count = 0
    };

}

static bool _index_append(Index *index, IndexEntry entry){
    if(index->entry_count == index->entry_buffer_size){
        size_t new_size = index->entry_buffer_size * ENTRY_COUNT_SCALING_FACTOR;
        assert(new_size > index->entry_buffer_size);
        IndexEntry *entries = calloc(new_size, sizeof(IndexEntry));
        if(entries == NULL){
            return false;
        }
        memcpy(entries, index->entries, index->entry_count * sizeof(IndexEntry));
        free(index->entries);
        index->entries = entries;
        index->entry_buffer_size = new_size;
    }

    index->entries[index->entry_count++] = entry;
    return true;
}

static const char *strnstr(const char *haystack, const char *needle, size_t len){
    size_t nl = strlen(needle);
    while(len >= nl){
        if(strncmp(haystack, needle, nl) == 0){
            return haystack;
        }
        haystack++;
        len--;
    }
    return NULL;
}

static bool _index_try_get_content_handle(Index *index, const char *path, size_t path_length, ContentHandle *handle){
    const char *query = strnstr(path, "?", path_length);
    LOG_DEBUG("q %s", query);
    if(query != NULL){
        path_length = query - path;
    }
    for(size_t i = 0; i < index->entry_count; i++){
        IndexEntry *entry = &index->entries[i];
        if(strlen(entry->path) == path_length && strncmp(entry->path, path, path_length) == 0){
            *handle = entry->content;
            return true;
        }
    }
    return false;
}

