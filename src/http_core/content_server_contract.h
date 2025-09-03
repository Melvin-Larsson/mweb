#ifndef CONTENT_SERVER_CONTRACT_H
#define CONTENT_SERVER_CONTRACT_H

#include <stddef.h>
#include <stdint.h>
#define START_OF_MESSAGE_IDENTIFIER 0x12345678

typedef enum{
    ContentRequest,
    ContentReply,
    ContentServerExit
}MessageType;

typedef struct{
    uint32_t start_of_message_identifier;
    MessageType type;
    size_t payload_length;
    uint32_t request_id;
    char payload[];
}MessageHeader;

#endif
