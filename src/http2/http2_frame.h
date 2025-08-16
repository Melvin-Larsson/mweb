#ifndef HTTP_FRAME_H
#define HTTP_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "buffers.h"

#define END_STREAM 0x1
#define END_HEADERS 0x4
#define PADDED 0x8
#define PRIORITY 0x20
#define ACK 0x1

typedef enum{
    ParseStatusSuccess = 0,
    ParseStatusMessageTooSmall,
    ParseSatusInvalidMessageSize,
    ParseStatusMissingPadding,
    ParseStatusMessageNotAllowdOnStream,
    ParseStatusInvalidFlags,
    ParseStatusSettingsAckWithBody,
    ParseStatusInvalidSettingsFormat,
    ParseStatusInvalidSetting,
    ParseStatusInvalidSizeIncrement,
}ParseStatus;

typedef enum{
    SettingsInvalid = 0,
    SettingsHeaderTableSize = 1,
    SettingsEnablePush = 2,
    SettingsMaxConcurrentStreams = 3,
    SettingsInitialWindowSize = 4,
    SettingsMaxFrameSize = 5,
    SettingsMaxHeaderListSize = 6,
    SettingsCount
}Setting;

typedef enum {
    ErrorCodeNoError             = 0x0,
    ErrorCodeProtocolError       = 0x1,
    ErrorCodeInternalError       = 0x2,
    ErrorCodeFlowControlError    = 0x3,
    ErrorCodeSettingsTimeout     = 0x4,
    ErrorCodeStreamClosed        = 0x5,
    ErrorCodeFrameSizeError      = 0x6,
    ErrorCodeRefusedStream       = 0x7,
    ErrorCodeCancel              = 0x8,
    ErrorCodeCompressionError    = 0x9,
    ErrorCodeConnectError        = 0xa,
    ErrorCodeEnhanceYourCalm     = 0xb,
    ErrorCodeInadequateSecurity  = 0xc,
    ErrorCodeHttp11Required      = 0xd
} ErrorCode;

typedef enum{
    Data = 0,
    Headers = 1,
    Priority = 2,
    RstStream = 3,
    Settings = 4,
    PushPromise = 5,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
    Invalid = 255
}FrameType;

typedef struct{
    uint32_t length : 24;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
}__attribute__((packed))ExternalFrameHeader;


typedef struct{
    FrameType type;
    uint8_t flags;
    uint32_t stream_id;
}InternalFrameHeader;

typedef struct{
    InternalFrameHeader header;
    char *data;
    size_t size;
}InternalDataFrame;

typedef struct{
    bool exclusive;
    uint32_t stream_dependency;
    uint8_t weight;
}InternalPriorityData;

typedef struct{
    InternalFrameHeader header;
    InternalPriorityData priority;
    char *header_block_fragment;
    size_t header_block_size;
}InternalHeaderFrame;

typedef struct{
    InternalFrameHeader header;
    InternalPriorityData priority;
}InternalPriorityFrame;

typedef struct{
    InternalFrameHeader header;
    uint32_t error_code;
}InternalRstStreamFrame;

typedef struct{
    bool is_present;
    uint32_t value;
}InternalSetting;

typedef struct{
    InternalFrameHeader header;
    InternalSetting settings[SettingsCount];
}InternalSettingsFrame;

typedef struct{
    InternalFrameHeader header;
    uint32_t promised_stream_id;
    char *header_block_fragment;
    size_t header_block_fragment_size;
}InternalPushPromiseFrame;

typedef struct{
    InternalFrameHeader header;
    uint64_t data;
}InternalPingFrame;

typedef struct{
    InternalFrameHeader header;
    uint32_t last_stream_id;
    uint32_t error_code;
    char *additional_data;
    size_t additional_data_size;
}InternalGoAwayFrame;

typedef struct{
    InternalFrameHeader header;
    uint32_t size_increment;
}InternalWindowUpdateFrame;

typedef struct{
    InternalFrameHeader header;
    char *header_block_fragment;
    size_t header_block_fragment_size;
}InternalContinuationFrame;

bool http2_frame_try_get_stream_id(uint8_t *buff, size_t len, uint32_t *stream_id);
bool http2_frame_try_get_length(uint8_t *buff, size_t buffer_size, size_t *length);

InternalDataFrame http2_frame_create_data_frame(uint8_t *data, size_t size, uint32_t stream_id);
ParseStatus http2_frame_parse_data_frame(ParseBuffer *buffer, InternalDataFrame *result);
size_t http2_frame_serialize_data_frame(char *buffer, size_t size, InternalDataFrame *frame);

InternalHeaderFrame http2_frame_create_header_frame(uint8_t *header_block_fragment, size_t size, size_t stream_id, bool is_last);
ParseStatus http2_frame_parse_header_frame(ParseBuffer *buffer, InternalHeaderFrame *result);
size_t http2_frame_serialize_header_frame(char *buffer, size_t size, InternalHeaderFrame *frame);

ParseStatus http2_frame_parse_priority_frame(ParseBuffer *buffer, InternalPriorityFrame *result);
size_t http2_frame_serialize_priority_frame(char *buffer, size_t size, InternalPriorityFrame *frame);

ParseStatus http2_frame_parse_rst_stream_frame(ParseBuffer *buffer, InternalRstStreamFrame *result);
size_t http2_frame_serialize_rst_stream_frame(char *buffer, size_t size, InternalRstStreamFrame *frame);

InternalSettingsFrame http2_frame_create_empty_settings_frame();
InternalSettingsFrame http2_frame_create_ack_settings_frame();
ParseStatus http2_frame_parse_settings_frame(ParseBuffer *buffer, InternalSettingsFrame *result);
size_t http2_frame_serialize_settings_frame(char *buffer, size_t size, InternalSettingsFrame *frame);

ParseStatus http2_frame_parse_push_promise_frame(ParseBuffer *buffer, InternalPushPromiseFrame *result);
size_t http2_frame_serialize_push_promise_frame(char *buffer, size_t size, InternalPushPromiseFrame *frame);

ParseStatus http2_frame_parse_ping_frame(ParseBuffer *buffer, InternalPingFrame *result);
size_t http2_frame_serialize_ping_frame(char *buffer, size_t size, InternalPingFrame *frame);

ParseStatus http2_frame_parse_goaway_frame(ParseBuffer *buffer, InternalGoAwayFrame *result);
size_t http2_frame_serialize_goaway_frame(char *buffer, size_t size, InternalGoAwayFrame *frame);

ParseStatus http2_frame_parse_window_update_frame(ParseBuffer *buffer, InternalWindowUpdateFrame *result);
size_t http2_serialize_window_update_frame(char *buffer, size_t size, InternalWindowUpdateFrame *frame);

ParseStatus http2_frame_parse_continuation_frame(ParseBuffer *buffer, InternalContinuationFrame *result);
size_t http2_frame_serialize_continuation_frame(char *buffer, size_t size, InternalContinuationFrame *frame);

void http2_frame_print_settings(InternalSettingsFrame *settings);

FrameType http2_frame_get_frame_type(char *buff, size_t len);

#endif
