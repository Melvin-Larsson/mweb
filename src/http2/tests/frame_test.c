#include "test_harness.h"
#include "http2/http2_frame.h"
#include <string.h>

static void _print_parse_buffer(ParseBuffer buffer){
    for(size_t i = 0; i < buffer.data_length; i++){
        printf("%X ", (uint8_t)buffer.data[i]);
    }
    printf("\n");
}

bool data_frame_serialize_deserialize(){
    //Setup
    char data[128];
    char buff[1024];

    memset(data, 69, sizeof(data));

    InternalDataFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 1,
            .type = Data
        },
        .data = data,
        .size = sizeof(data)
    };

    //Act
    size_t used_size = http2_serialize_data_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalDataFrame actual;
    ParseStatus status = http2_frame_parse_data_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 9 + sizeof(data));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_BYTES_EQUAL(expected.data, expected.size, actual.data, actual.size);

    return true;
}

bool header_frame_serialize_deserialize(){
    //Setup
    char header_block_fragment[128];
    char buff[1024];

    memset(header_block_fragment, 69, sizeof(header_block_fragment));

    InternalHeaderFrame expected = {
        .header = {
            .flags = PRIORITY,
            .stream_id = 1,
            .type = Headers
        },
        .priority = {
            .exclusive = true,
            .stream_dependency = 123,
            .weight = 69
        },
        .header_block_fragment = header_block_fragment,
        .header_block_size = sizeof(header_block_fragment),
    };

    //Act
    size_t used_size = http2_frame_serialize_header_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalHeaderFrame actual;
    ParseStatus status = http2_frame_parse_header_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 14 + sizeof(header_block_fragment));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.priority.exclusive, actual.priority.exclusive);
    ASSERT_INT_EQUAL(expected.priority.stream_dependency, actual.priority.stream_dependency);
    ASSERT_INT_EQUAL(expected.priority.weight, actual.priority.weight);
    ASSERT_BYTES_EQUAL(expected.header_block_fragment, expected.header_block_size, actual.header_block_fragment, actual.header_block_size);

    return true;
}

bool priority_frame_serialize_deserialize(){
    //Setup
    char buff[1024];

    InternalPriorityFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 1,
            .type = Priority
        },
        .priority.exclusive = false,
        .priority.stream_dependency = 123,
        .priority.weight = 69
    };

    //Act
    size_t used_size = http2_frame_serialize_priority_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalPriorityFrame actual;
    ParseStatus status = http2_frame_parse_priority_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.priority.exclusive, actual.priority.exclusive)
    ASSERT_INT_EQUAL(expected.priority.stream_dependency, actual.priority.stream_dependency)
    ASSERT_INT_EQUAL(expected.priority.weight, actual.priority.weight);

    return true;
}

bool rst_stream_frame_serialize_deserialize(){
    //Setup
    char buff[1024];

    InternalRstStreamFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 0,
            .type = RstStream
        },
        .error_code = ErrorCodeConnectError,
    };

    //Act
    size_t used_size = http2_frame_serialize_rst_stream_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalRstStreamFrame actual;
    ParseStatus status = http2_frame_parse_rst_stream_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.error_code, actual.error_code);

    return true;
}

bool settings_frame_serialize_deserialize(){
    //Setup
    char buff[1024];

    InternalSettingsFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 0,
            .type = Settings
        },
        .settings[1] = {
            .is_present = true,
            .value = 69,
        },
        .settings[2] = {
            .is_present = true,
            .value = 1,
        },
        .settings[6] = {
            .is_present = true,
            .value = 128
        }
    };

    //Act
    size_t used_size = http2_frame_serialize_settings_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalSettingsFrame actual;
    ParseStatus status = http2_frame_parse_settings_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);

    _print_parse_buffer(buffer);

    for(size_t i = 1; i < SettingsCount; i++){
        ASSERT_INT_EQUAL(expected.settings[i].is_present, actual.settings[i].is_present);
        if(expected.settings[i].is_present){
            printf("i %d\n", i);
            ASSERT_INT_EQUAL(expected.settings[i].value, actual.settings[i].value);
        }
    }

    return true;
}
bool push_promise_frame_serialize_deserialize(){
    //Setup
    char data[128];
    char buff[1024];

    memset(data, 128, sizeof(data));

    InternalPushPromiseFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 1,
            .type = PushPromise
        },

        .header_block_fragment = data,
        .header_block_fragment_size = sizeof(data),
        .promised_stream_id = 128,
    };

    //Act
    size_t used_size = http2_frame_serialize_push_promise_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalPushPromiseFrame actual;
    ParseStatus status = http2_frame_parse_push_promise_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 13 + sizeof(data));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_BYTES_EQUAL(expected.header_block_fragment, expected.header_block_fragment_size, actual.header_block_fragment, actual.header_block_fragment_size);
    ASSERT_INT_EQUAL(expected.promised_stream_id, actual.promised_stream_id);

    return true;
}

bool ping_frame_serialize_deserialize(){
    //Setup
    uint64_t data;
    char buff[1024];

    memset(&data, 69, sizeof(data));

    InternalPingFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 0,
            .type = Ping
        },
        .data = data
    };

    //Act
    size_t used_size = http2_frame_serialize_ping_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalPingFrame actual;
    ParseStatus status = http2_frame_parse_ping_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 9 + sizeof(data));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.data, actual.data);

    return true;
}

bool goaway_frame_serialize_deserialize(){
    //Setup
    char data[128];
    char buff[1024];

    memset(data, 69, sizeof(data));

    InternalGoAwayFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 0,
            .type = GoAway
        },
        .error_code = 128,
        .additional_data = data,
        .additional_data_size = sizeof(data),
    };

    //Act
    size_t used_size = http2_frame_serialize_goaway_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalGoAwayFrame actual;
    ParseStatus status = http2_frame_parse_goaway_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 17 + sizeof(data));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.error_code, actual.error_code);
    ASSERT_BYTES_EQUAL(expected.additional_data, expected.additional_data_size, actual.additional_data, actual.additional_data_size);

    return true;
}

bool window_update_frame_serialize_deserialize(){
    //Setup
    char buff[1024];

    InternalWindowUpdateFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 1,
            .type = Data
        },
        .size_increment = 128
    };

    //Act
    size_t used_size = http2_serialize_window_update_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalWindowUpdateFrame actual;
    ParseStatus status = http2_frame_parse_window_update_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, (size_t)13);
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_INT_EQUAL(expected.size_increment, actual.size_increment);


    return true;
}

bool continuation_frame_serialize_deserialize(){
    //Setup
    char data[128];
    char buff[1024];

    memset(data, 69, sizeof(data));

    InternalContinuationFrame expected = {
        .header = {
            .flags = 0,
            .stream_id = 1,
            .type = Continuation
        },
        .header_block_fragment = data,
        .header_block_fragment_size = sizeof(data)
    };

    //Act
    size_t used_size = http2_frame_serialize_continuation_frame(buff, sizeof(buff), &expected);
    ParseBuffer buffer = {.data = buff, .data_length = used_size, .parsed_length = 0};
    InternalContinuationFrame actual;
    ParseStatus status = http2_frame_parse_continuation_frame(&buffer, &actual);

    //Assert
    ASSERT_INT_EQUAL(ParseStatusSuccess, status);
    ASSERT_SIZE_EQUAL(used_size, 9 + sizeof(data));
    ASSERT_SIZE_EQUAL(buffer.data_length, buffer.parsed_length);
    ASSERT_INT_EQUAL(expected.header.flags, actual.header.flags);
    ASSERT_INT_EQUAL(expected.header.stream_id, actual.header.stream_id);
    ASSERT_INT_EQUAL(expected.header.type, actual.header.type);
    ASSERT_BYTES_EQUAL(expected.header_block_fragment, expected.header_block_fragment_size, actual.header_block_fragment, actual.header_block_fragment_size);

    return true;
}


Test tests[] = {
    TEST(data_frame_serialize_deserialize),
    TEST(header_frame_serialize_deserialize),
    TEST(priority_frame_serialize_deserialize),
    TEST(rst_stream_frame_serialize_deserialize),
    TEST(settings_frame_serialize_deserialize),
    TEST(push_promise_frame_serialize_deserialize),
    TEST(ping_frame_serialize_deserialize),
    TEST(goaway_frame_serialize_deserialize),
    TEST(window_update_frame_serialize_deserialize),
    TEST(continuation_frame_serialize_deserialize),
};
const size_t test_count = sizeof(tests) / sizeof(Test);

