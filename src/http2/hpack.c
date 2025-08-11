#include "http2/hpack.h"
#include <stdlib.h>

struct HpackCtx{
    char *dynamic_table;
    size_t dynamic_table_size_bytes;

};

HpackCtx *hpack_new_ctx(size_t dynamic_table_size_bytes){
    HpackCtx *ctx = malloc(sizeof(HpackCtx));
    if(ctx == NULL){
        return NULL;
    }

    ctx->dynamic_table = malloc(dynamic_table_size_bytes);
    ctx->dynamic_table_size_bytes = dynamic_table_size_bytes;
    if(!ctx->dynamic_table){
        goto exit_ctx;
    }

exit_dynamic_table:
    free(ctx->dynamic_table);
exit_ctx:
    free(ctx);
    return NULL;
}

