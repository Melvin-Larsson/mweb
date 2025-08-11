#ifndef HPACK_H
#define HPACK_H

#include <stddef.h>

typedef struct HpackCtx HpackCtx;

HpackCtx *hpack_new_ctx(size_t dynamic_table_size_bytes);

#endif
