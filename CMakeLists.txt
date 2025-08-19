cmake_minimum_required(VERSION 3.16)
project(web)

enable_testing()

set(SERVER_SOURCES
    src/server/server.c
    src/server/server_worker.c
    src/server/config_manager.c
)

set(HTTP2_SOURCES
    src/http2/http2.c
    src/http2/stream/stream_idle.c
    src/http2/stream/stream_open.c
    src/http2/stream/stream_half_closed_remote.c
    src/http2/stream/stream_default.c
    src/http2/http2_common.c
    src/http2/utils.c


    src/http2/http2_frame.c
    src/http2/frames/continuation_frame.c
    src/http2/frames/data_frame.c
    src/http2/frames/frame_utils.c
    src/http2/frames/goaway_frame.c
    src/http2/frames/header_frame.c
    src/http2/frames/ping_frame.c
    src/http2/frames/priority_frame.c
    src/http2/frames/push_promise_frame.c
    src/http2/frames/rst_stream_frame.c
    src/http2/frames/settings_frame.c
    src/http2/frames/window_update_frame.c

    src/http2/hpack.c
    src/http2/hpack_primitives.c
    src/http2/huffman.c
    src/http2/bit_stream.c

)

set(HTTP_CORE_SOURCES
    src/http_core/http_core.c
    src/http_core/stringbuilder.c
)

set(THREADPOOL_SOURCES
    src/threadpool/threadpool.c
    src/threadpool/queue.c
)

add_library(libserver ${SERVER_SOURCES})
add_library(libhttp2 ${HTTP2_SOURCES})
add_library(libhttpcore ${HTTP_CORE_SOURCES})
add_library(libthreadpool ${THREADPOOL_SOURCES})

configure_file(cert/cert.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(cert/key.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(config.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(CJSON REQUIRED libcjson)

target_include_directories(libserver PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(libserver PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(libserver PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_libraries(libserver PRIVATE ${CJSON_LIBRARIES})
target_include_directories(libserver PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libserver PRIVATE ${PROJECT_SOURCE_DIR}/src/server ${PROJECT_SOURCE_DIR}/src/common)
target_link_libraries(libserver PRIVATE libhttp2)
target_link_libraries(libserver PRIVATE libthreadpool)

target_include_directories(libhttp2 PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libhttp2 PRIVATE ${PROJECT_SOURCE_DIR}/src/http2 ${PROJECT_SOURCE_DIR}/src/common)
target_link_libraries(libhttp2 PRIVATE libhttpcore)

target_include_directories(libhttpcore PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_libraries(libhttpcore PRIVATE ${CJSON_LIBRARIES})
target_include_directories(libhttpcore PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libhttpcore PRIVATE ${PROJECT_SOURCE_DIR}/src/http_core ${PROJECT_SOURCE_DIR}/src/common)

target_include_directories(libthreadpool PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libthreadpool PRIVATE ${PROJECT_SOURCE_DIR}/src/threadpool)

set(TARGET_NAME web)
add_executable(${TARGET_NAME} src/main.c)
target_link_libraries(${TARGET_NAME} libserver)

add_executable(frame_test src/http2/tests/frame_test.c)
target_link_libraries(frame_test libhttp2)
target_include_directories(frame_test PRIVATE ${PROJECT_SOURCE_DIR}/src/http2)

add_executable(hpack_test src/http2/tests/hpack_test.c)
target_link_libraries(hpack_test libhttp2)
target_include_directories(hpack_test PRIVATE ${PROJECT_SOURCE_DIR}/src/http2)

add_executable(bit_stream_test src/http2/tests/bit_stream_test.c)
target_link_libraries(bit_stream_test libhttp2)
target_include_directories(bit_stream_test PRIVATE ${PROJECT_SOURCE_DIR}/src/http2)

add_test(NAME FrameParser COMMAND frame_test)
add_test(NAME Hpack COMMAND hpack_test)
add_test(NAME BitStream COMMAND bit_stream_test)
