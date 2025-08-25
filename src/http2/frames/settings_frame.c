#include "http2_frame.h"
#include "frame_utils.h"
#include "assert.h"
#include <string.h>

#define LOG_CONTEXT "Http2"
#include "logging.h"

InternalSettingsFrame http2_frame_create_empty_settings_frame(){
    return (InternalSettingsFrame){
        .header = (InternalFrameHeader){
            .flags = 0,
            .stream_id = 0,
            .type = Settings
        },
    };
}

InternalSettingsFrame http2_frame_create_ack_settings_frame(){
    return (InternalSettingsFrame){
        .header = (InternalFrameHeader){
            .flags = ACK,
            .stream_id = 0,
            .type = Settings
        },
    };
}

ParseStatus http2_frame_parse_settings_frame(ParseBuffer *buffer, InternalSettingsFrame *result){
    InternalFrameHeader header;
    Payload payload_info;
    ParseStatus status = http2_frame_parse_frame_header(buffer, &header, &payload_info);
    if(status != ParseStatusSuccess){
        return status;
    }
    assert(header.type == Settings);

    if(header.stream_id != 0){
        return ParseStatusMessageNotAllowdOnStream;
    }

    result->header = header;

    if(header.flags & ACK){
        if(payload_info.size != 0){
            return ParseStatusSettingsAckWithBody;
        }
        return ParseStatusSuccess;
    }

    if(payload_info.size % 6 != 0){
        return ParseStatusInvalidSettingsFormat;
    }

    size_t settings_count = payload_info.size / 6;
    memset(result->settings, 0, sizeof(result->settings));

    unsigned char *setting_bytes = payload_info.data;
    for(size_t i = 0; i < settings_count; i++){
        uint16_t settings_id = setting_bytes[0] << 16 | setting_bytes[1];
        uint32_t settings_value = setting_bytes[2] << 24 | setting_bytes[3] << 16 | setting_bytes[4] << 8 | setting_bytes[5];

        if(settings_id == SettingsInvalid || settings_id  >= SettingsCount){
            ERROR("Invalid setting %d received", settings_id);
            return ParseStatusInvalidSetting;
        }

        result->settings[settings_id] = (InternalSetting){
            .is_present = true,
            .value = settings_value
        };

        setting_bytes += 6;
    }

    return ParseStatusSuccess;
}

size_t http2_frame_serialize_settings_frame(char *buffer, size_t size, InternalSettingsFrame *frame){
    assert(frame->header.stream_id == 0);

    frame->header.type = Settings;

    if(frame->header.flags & ACK){
        Payload payload_info;
        return http2_frame_serialize_frame_header(buffer, size, 0, &frame->header, &payload_info);
    }

    size_t settings_count = 0;
    for(size_t i = 1; i < SettingsCount; i++){
        if(frame->settings[i].is_present){
            settings_count++;
        }
    }

    Payload paylod_info;
    size_t used_size = http2_frame_serialize_frame_header(buffer, size, settings_count * 6, &frame->header, &paylod_info);

    for(size_t i = 1; i < SettingsCount; i++){
        InternalSetting *setting = &frame->settings[i];
        if(setting->is_present){
            char identifer[2] = {(i & 0xFF00) >> 8, i & 0xFF};
            char value[4] = {(setting->value & 0xFF000000) >> 24, (setting->value & 0xFF0000) >> 16, (setting->value & 0xFF00) >> 8, setting->value & 0xFF};

            _append_bytes(&paylod_info.data, &paylod_info.size, identifer, 2);
            _append_bytes(&paylod_info.data, &paylod_info.size, value, 4);
        }
    }

    return used_size;
}

void http2_frame_print_settings(InternalSettingsFrame *settings){
    assert(settings != NULL);
    assert(settings->header.type == Settings);

    LOG_DEBUG("==Settings==");
    for(size_t i = 1; i < SettingsCount; i++){
        InternalSetting *setting = &settings->settings[i];
        if(setting->is_present == false){
            continue;
        }
        switch(i){
            case SettingsHeaderTableSize:
                LOG_DEBUG("Header table size: %d", setting->value);
                break;
            case SettingsEnablePush:
                LOG_DEBUG("Enable push: %d", setting->value);
                break;
            case SettingsMaxConcurrentStreams:
                LOG_DEBUG("Max concurrent streams: %d", setting->value);
                break;
            case SettingsInitialWindowSize:
                LOG_DEBUG("Initial window size: %d", setting->value);
                break;
            case SettingsMaxHeaderListSize:
                LOG_DEBUG("Max header list size: %d", setting->value);
                break;
        }
    }
}

