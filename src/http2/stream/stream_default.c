#include "http2_common.h"
#include "http2_frame.h"
#include "http2_logging.h"
#include "stream.h"
#include <assert.h>
#include <stdlib.h>

static void _handle_settings(Http2Client *client, InternalSettingsFrame frame);
static void _handle_window_update(Http2Client *client, InternalWindowUpdateFrame frame);
static void _handle_ping(Http2Client *client, InternalPingFrame frame);

void default_stream_handle_message(Http2Client *client, const GenericFrame *frame){
    switch(frame->type){
        case Settings:
            _handle_settings(client, frame->settings_frame);
            break;
        case WindowUpdate:
            client->window_size += frame->window_update_frame.size_increment;
            return;
        case GoAway:
            LOG_DEBUG("Go away received, reason %d", frame->goaway_frame.error_code);
            return;
        default:
            ERROR("Unable to handle frame of type %d on default stream", frame->type);
            http2_common_send_goaway(client, ErrorCodeProtocolError);
            break;
    }
}

void _handle_settings(Http2Client *client, InternalSettingsFrame frame){
    if(frame.header.flags & ACK){
        LOG_DEBUG("Settings acked");
        return;
    }

    uint8_t buffer[4096];
    http2_frame_print_settings(&frame);

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
