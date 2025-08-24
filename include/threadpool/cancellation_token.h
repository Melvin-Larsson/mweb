#ifndef CANCELLATION_TOKEN_H
#define CANCELLATION_TOKEN_H

#include "collections/slot_map.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct CancellationToken CancellationToken;
typedef struct CancellationTokenFactory CancellationTokenFactory;

typedef struct{
    void (*on_cancel)(void *u_data);
    void *u_data;
}CancellationTokenCallback;

typedef struct{
    SlotMapHandle handle;
}CancellationTokenCallbackHandle;


CancellationTokenFactory *cancellation_token_factory_new();
CancellationToken *cancellation_token_factory_create_token(CancellationTokenFactory *factory);
void cancellation_token_factory_cancel_and_free(CancellationTokenFactory *factory);

bool cancellation_token_add_callback(CancellationToken *token, CancellationTokenCallback callback, CancellationTokenCallbackHandle *result);
void cancellation_token_remove_callback(CancellationToken *token, CancellationTokenCallbackHandle handle);

#endif
