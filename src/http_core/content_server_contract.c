#include "content_server_contract.h"
#include <stdalign.h>

struct ReplySerializerContext{
    Buffer *buffer;
};

struct RequestSerializerContext{
    Buffer *buffer;
};

static void serialize_var_length_fields(VarLengthField *fields, size_t count, Buffer *buffer);
static DeserializeStatus deserialize_var_length_fields(ParseBuffer *parse_buffer, size_t size, VarLengthField **result, size_t *result_count, Buffer *result_buffer);

ReplySerializerContext *reply_serialier_context_create(Buffer *buffer, uint64_t request_id){
    ReplySerializerContext *ctx = buffer_allocate_aligned(buffer, sizeof(ReplySerializerContext), alignof(ReplySerializerContext));
    if(ctx == NULL){
        return NULL;
    }

    *ctx = (ReplySerializerContext){
        .buffer = buffer
    };

    ContentReplyMessage message = {
        .request_id = request_id,
        .content = NULL,
        .content_count = 0
    };

    serialize_content_reply(message, buffer);

    return ctx;
}

void reply_serializer_context_add_content(ReplySerializerContext *ctx, const char *content, size_t content_length){
    VarLengthField field = {
        .length = content_length,
        .value = content
    };
    serialize_var_length_fields(&field, 1, ctx->buffer);
}

uint8_t *reply_serializer_context_serialize(ReplySerializerContext *ctx, size_t *size){
    if(buffer_size_is_full(ctx->buffer)){
        return NULL;
    }

    uint8_t *result = (uint8_t *)ctx + sizeof(ReplySerializerContext);
    *size = buffer_get_append_ptr(ctx->buffer) - result;

    MessageHeader *header = (MessageHeader *)result;
    header->payload_length = *size - sizeof(MessageHeader);

    return result;
}

RequestSerializerContext *request_serialier_context_create(Buffer *buffer, uint64_t request_id){
    RequestSerializerContext *ctx = buffer_allocate_aligned(buffer, sizeof(RequestSerializerContext), alignof(RequestSerializerContext));
    if(ctx == NULL){
        return NULL;
    }

    *ctx = (RequestSerializerContext){
        .buffer = buffer
    };

    ContentRequestMessage message = {
        .request_id = request_id,
        .tags = NULL,
        .tag_count = 0
    };

    serialize_content_request(message, buffer);

    return ctx;

}

void request_serializer_context_add_tag(RequestSerializerContext *ctx, const char *tag, size_t tag_length){
    VarLengthField field = {
        .length = tag_length,
        .value = tag
    };
    serialize_var_length_fields(&field, 1, ctx->buffer);
}

uint8_t *request_serializer_context_serialize(RequestSerializerContext *ctx, size_t *size){
    if(buffer_size_is_full(ctx->buffer)){
        return NULL;
    }

    uint8_t *result = (uint8_t *)ctx + sizeof(RequestSerializerContext);
    *size = buffer_get_append_ptr(ctx->buffer) - result;

    MessageHeader *header = (MessageHeader *)result;
    header->payload_length = *size - sizeof(MessageHeader);

    return result;
}

void serialize_content_request(ContentRequestMessage message, Buffer *buffer){
    size_t payload_length;
    for(size_t i = 0; i < message.tag_count; i++){
        payload_length += sizeof(uint32_t) + message.tags[i].length;
    }

    MessageHeader header = {
        .start_of_message_identifier = START_OF_MESSAGE_IDENTIFIER,
        .request_id = message.request_id,
        .type = ContentRequest,
        .payload_length = payload_length
    };
    buffers_append(buffer, &header, sizeof(header));

    serialize_var_length_fields(message.tags, message.tag_count, buffer);
}

void serialize_content_reply(ContentReplyMessage message, Buffer *buffer){
    size_t payload_length;
    for(size_t i = 0; i < message.content_count; i++){
        payload_length += sizeof(uint32_t) + message.content[i].length;
    }

    MessageHeader header = {
        .start_of_message_identifier = START_OF_MESSAGE_IDENTIFIER,
        .request_id = message.request_id,
        .type = ContentReply,
        .payload_length = payload_length
    };
    buffers_append(buffer, &header, sizeof(header));

    serialize_var_length_fields(message.content, message.content_count, buffer);
}

DeserializeStatus deserialize_content_request(ParseBuffer *buffer, ContentRequestMessage *result, Buffer *result_buffer){
    DeserializeStatus status;
    size_t initial_parsed_size = buffer->parsed_size;
    size_t initial_used_size = result_buffer->used_size;

    if(parse_buffer_size_left(buffer) < sizeof(MessageHeader)){
        status = DeserializeStatusNotEnoughData;
        goto exit;
    }

    MessageHeader *header = (MessageHeader *)parse_buffer_parse(buffer, sizeof(MessageHeader));

    if(header->start_of_message_identifier != START_OF_MESSAGE_IDENTIFIER){
        status = DeserializeStatusInvalidStartOfMessageIdentifier;
        goto exit;
    }
    if(header->type != ContentRequest){
        status = DeserializeStatusInvalidType;
        goto exit;
    }

    if(parse_buffer_size_left(buffer) < header->payload_length){
        status = DeserializeStatusNotEnoughData;
        goto exit;
    }

    VarLengthField *fields;
    size_t count;
    status = deserialize_var_length_fields(buffer, header->payload_length, &fields, &count, result_buffer);
    if(status != DeserializeStatusOk){
        goto exit;
    }

    *result = (ContentRequestMessage){
        .request_id = header->request_id,
        .tag_count = count,
        .tags = fields
    };

    return DeserializeStatusOk;

exit:
    buffer->parsed_size = initial_parsed_size;
    result_buffer->used_size = initial_used_size;
    return status;
}

DeserializeStatus deserialize_content_reply(ParseBuffer *buffer, ContentReplyMessage *result, Buffer *result_buffer){
    DeserializeStatus status;
    size_t initial_parsed_size = buffer->parsed_size;
    size_t initial_used_size = result_buffer->used_size;

    if(parse_buffer_size_left(buffer) < sizeof(MessageHeader)){
        status = DeserializeStatusNotEnoughData;
        goto exit;
    }

    MessageHeader *header = (MessageHeader *)parse_buffer_parse(buffer, sizeof(MessageHeader));

    if(header->start_of_message_identifier != START_OF_MESSAGE_IDENTIFIER){
        status = DeserializeStatusInvalidStartOfMessageIdentifier;
        goto exit;
    }
    if(header->type != ContentReply){
        status = DeserializeStatusInvalidType;
        goto exit;
    }

    if(parse_buffer_size_left(buffer) < header->payload_length){
        status = DeserializeStatusNotEnoughData;
        goto exit;
    }

    VarLengthField *fields;
    size_t count;
    status = deserialize_var_length_fields(buffer, header->payload_length, &fields, &count, result_buffer);
    if(status != DeserializeStatusOk){
        goto exit;
    }

    *result = (ContentReplyMessage){
        .request_id = header->request_id,
        .content_count = count,
        .content = fields
    };

    return DeserializeStatusOk;

exit:
    buffer->parsed_size = initial_parsed_size;
    result_buffer->used_size = initial_used_size;
    return status;
}

const char *deserialize_status_str(DeserializeStatus status){
    switch(status){
        case DeserializeStatusOk:
            return "Ok";
        case DeserializeStatusNotEnoughData:
            return "Not enough data";
        case DeserializeStatusInvalidStartOfMessageIdentifier:
            return "Invalid start of message identified";
        case DeserializeStatusInvalidType:
            return "Invalid message type";
        case DeserializeStatusVarLengthFieldsInvalidSize:
            return "Invalid lengths for variable length fields";
        case DeserializeStatusNotEnoughMemory:
            return "Not enough memory";
    }
    return "Unknown status";
}

static void serialize_var_length_fields(VarLengthField *fields, size_t count, Buffer *buffer){
    for(size_t i = 0; i < count; i++){
        buffers_append(buffer, &fields[i].length, sizeof(uint32_t));
        buffers_append(buffer, (uint8_t *)fields[i].value, fields[i].length);
    }
}

static DeserializeStatus deserialize_var_length_fields(ParseBuffer *parse_buffer, size_t size, VarLengthField **result, size_t *result_count, Buffer *result_buffer){
    uint8_t *data_ptr = parse_buffer_get_parse_ptr(parse_buffer);
    size_t offset = 0;
    *result_count = 0;
    while(true){
        uint32_t len;
        memcpy(&len, &data_ptr[offset], sizeof(uint32_t));

        offset += len + sizeof(uint32_t);
        (*result_count)++;

        if(offset == size){
            break;
        }
        else if(offset > size){
            return DeserializeStatusVarLengthFieldsInvalidSize;
        }
    }

    *result = buffer_allocate(result_buffer, *result_count * sizeof(VarLengthField));
    uint8_t *value_buffer = buffer_allocate(result_buffer, size  - (*result_count)  * sizeof(uint32_t));

    if(*result == NULL || value_buffer == NULL){
        return DeserializeStatusNotEnoughMemory;
    }

    uint8_t *insert_point = value_buffer;
    uint8_t *parse_point = parse_buffer_get_parse_ptr(parse_buffer);
    for(size_t i = 0; i < *result_count; i++){
        uint32_t len;
        memcpy(&len, parse_point, sizeof(uint32_t));

        memcpy(insert_point, parse_point + sizeof(uint32_t), len);
        (*result)[i] = (VarLengthField){
            .value = (char *)insert_point,
            .length = len
        };

        insert_point += len;
        parse_point += len + sizeof(uint32_t);
    }

    parse_buffer_parse(parse_buffer, size);

    return DeserializeStatusOk;
}
