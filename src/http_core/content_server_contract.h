#ifndef CONTENT_SERVER_CONTRACT_H
#define CONTENT_SERVER_CONTRACT_H

#include "buffers.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define START_OF_MESSAGE_IDENTIFIER 0x12345678

typedef enum{
    DeserializeStatusOk,
    DeserializeStatusNotEnoughData,
    DeserializeStatusInvalidStartOfMessageIdentifier,
    DeserializeStatusInvalidType,
    DeserializeStatusVarLengthFieldsInvalidSize,
    DeserializeStatusNotEnoughMemory
}DeserializeStatus;

typedef enum{
    ContentRequest,
    ContentReply,
    ContentServerExit
}MessageType;

typedef struct{
    uint32_t start_of_message_identifier;
    MessageType type;
    size_t payload_length;
    uint64_t request_id;
    char payload[];
}MessageHeader;

typedef struct{
    size_t length;
    const char *value;
}VarLengthField;

typedef struct{
    uint64_t request_id;
    size_t tag_count;
    VarLengthField *tags;
}ContentRequestMessage;

typedef struct{
    uint64_t request_id;
    size_t content_count;
    VarLengthField *content;
}ContentReplyMessage;

typedef struct ReplySerializerContext ReplySerializerContext;
typedef struct RequestSerializerContext RequestSerializerContext;

RequestSerializerContext *request_serialier_context_create(Buffer *buffer, uint64_t request_id);
void request_serializer_context_add_tag(RequestSerializerContext *ctx, const char *tag, size_t tag_length);
uint8_t *request_serializer_context_serialize(RequestSerializerContext *ctx, size_t *size);

ReplySerializerContext *reply_serialier_context_create(Buffer *buffer, uint64_t request_id);
void reply_serializer_context_add_content(ReplySerializerContext *ctx, const char *content, size_t content_length);
uint8_t *reply_serializer_context_serialize(ReplySerializerContext *ctx, size_t *size);


void serialize_content_request(ContentRequestMessage message, Buffer *buffer);
void serialize_content_reply(ContentReplyMessage message, Buffer *buffer);

DeserializeStatus deserialize_content_request(ParseBuffer *buffer, ContentRequestMessage *result, Buffer *result_buffer);
DeserializeStatus deserialize_content_reply(ParseBuffer *buffer, ContentReplyMessage *result, Buffer *result_buffer);

const char *deserialize_status_str(DeserializeStatus status);

#endif
