#include "threadpool/cancellation_token.h"
#include "collections/arraylist.h"
#include "collections/slot_map.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct CancellationToken{
    SlotMap *callbacks;
};
struct CancellationTokenFactory{
    ArrayList *tokens;
};

void _cancel_and_free_token(CancellationToken *token);

CancellationTokenFactory *cancellation_token_factory_new(){
    CancellationTokenFactory *factory = malloc(sizeof(CancellationTokenFactory));
    ArrayList *tokens = array_list_new(sizeof(CancellationToken *));
    if(factory == NULL || tokens == NULL){
        free(factory);
        array_list_free(tokens);
        return NULL;
    }

    *factory = (CancellationTokenFactory){
        .tokens = tokens
    };

    return factory;
}

CancellationToken *cancellation_token_factory_create_token(CancellationTokenFactory *factory){
    CancellationToken *token = malloc(sizeof(CancellationToken));
    SlotMap *callbacks = slot_map_new(sizeof(CancellationTokenCallback));
    if(token == NULL || callbacks == NULL){
        goto exit;
    }

    *token = (CancellationToken){
        .callbacks = callbacks
    };

    if(!array_list_add(factory->tokens, &token)){
        goto exit;
    }

    return token;

exit:
    free(token);
    slot_map_free(callbacks);
    return NULL;
}

void cancellation_token_factory_cancel_and_free(CancellationTokenFactory *factory){
    size_t size = array_list_size(factory->tokens);
    for(size_t i = 0; i < size; i++){
        CancellationToken *token;
        array_list_get(factory->tokens, i, &token);
        _cancel_and_free_token(token);
    }

    array_list_free(factory->tokens);
    free(factory);
}

void _cancel_and_free_token(CancellationToken *token){
    SlotMapIterator *iterator = slot_map_create_iterator(token->callbacks);
    if(iterator == NULL){
        fprintf(stderr, "Unable to allocate iterator for cancellation token");
        abort();
    }
    CancellationTokenCallback callback;
    while(slot_map_iterator_next(iterator, &callback)){
        callback.on_cancel(callback.u_data);
    }
    slot_map_iterator_free(iterator);

    slot_map_free(token->callbacks);
    free(token);
}

bool cancellation_token_add_callback(CancellationToken *token, CancellationTokenCallback callback, CancellationTokenCallbackHandle *result){
    return slot_map_try_add(token->callbacks, &callback, &result->handle);
}

void cancellation_token_remove_callback(CancellationToken *token, CancellationTokenCallbackHandle handle){
    slot_map_remove(token->callbacks, handle.handle);
}
