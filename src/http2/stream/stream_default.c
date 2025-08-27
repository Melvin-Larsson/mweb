#include "http2_common.h"
#include "http2_frame.h"
#include "stream.h"
#include <assert.h>
#include <stdlib.h>

#define LOG_CONTEXT "Http2"
#include "logging.h"

static void _handle_settings(Http2Client *client, InternalSettingsFrame frame);
static void _handle_window_update(Http2Client *client, InternalWindowUpdateFrame frame);
static void _handle_ping(Http2Client *client, InternalPingFrame frame);

Task default_stream_handle_message_async(Http2Client *client, const GenericFrame *frame, CancellationToken *token){
    switch(frame->type){
        case Settings:
            _handle_settings(client, frame->settings_frame);
            break;
        case WindowUpdate:
            LOG_TRACE("Increase connection window size %d + %d = %d", client->window_size, frame->window_update_frame.size_increment, client->window_size + frame->window_update_frame.size_increment);
            client->window_size += frame->window_update_frame.size_increment;
            //FIXME: send waiting clients
            break;
        case GoAway:
            LOG_DEBUG("Go away received, reason %d", frame->goaway_frame.error_code);
            break;
        case Ping:
            {
                InternalPingFrame ping_frame = frame->ping_frame;
                ping_frame.header.flags |= ACK;
                uint8_t buffer[128];
                size_t frame_size = http2_frame_serialize_ping_frame((char *)buffer, sizeof(buffer), &ping_frame);
                assert(frame_size < sizeof(buffer));
                http2_common_send(client, buffer, frame_size);
                break;
            }
        default:
            ERROR("Unable to handle frame of type %d on default stream", frame->type);
            http2_common_send_goaway(client, ErrorCodeProtocolError);
            break;
    }

    return completed_task();
}

void _apply_settings(Http2Client *client, InternalSettingsFrame settings){
    if(settings.settings[SettingsInitialWindowSize].is_present){
        client->initial_window_size = settings.settings[SettingsInitialWindowSize].value;
        client->window_size = client->initial_window_size;
    }
    if(settings.settings[SettingsMaxFrameSize].is_present){
        client->max_frame_size = settings.settings[SettingsMaxFrameSize].value;
    }
}

void _handle_settings(Http2Client *client, InternalSettingsFrame frame){
    if(frame.header.flags & ACK){
        LOG_DEBUG("Settings acked");
        return;
    }

    uint8_t buffer[4096];
    http2_frame_print_settings(&frame);

    _apply_settings(client, frame);

    LOG_DEBUG("Sending empty settings frame...");
    InternalSettingsFrame server_settings_frame = http2_frame_create_empty_settings_frame();
    size_t server_settings_frame_size = http2_frame_serialize_settings_frame((char *)buffer, sizeof(buffer), &server_settings_frame);
    assert(server_settings_frame_size < sizeof(buffer));
    http2_common_send(client, buffer, server_settings_frame_size);

    LOG_DEBUG("Sending ack frame...");
    InternalSettingsFrame ack_frame = http2_frame_create_ack_settings_frame();
    size_t ack_frame_size =  http2_frame_serialize_settings_frame((char *)buffer, sizeof(buffer), &ack_frame);
    assert(ack_frame_size < sizeof(buffer));
    http2_common_send(client, buffer, ack_frame_size);
}

static void _handle_ping(Http2Client *client, InternalPingFrame frame){
    InternalPingFrame response = http2_frame_create_ping_frame(true, frame.data);
    uint8_t buffer[128];
    size_t size = http2_frame_serialize_ping_frame((char *)buffer, sizeof(buffer), &response);
    assert(size < sizeof(buffer));
    http2_common_send(client, buffer, size);
}
