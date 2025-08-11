cmake_minimum_required(VERSION 3.16)
project(web)

enable_testing()

set(SOURCES
    src/server.c
    src/stringbuilder.c
    src/server_worker.c
    src/config_manager.c

    src/http2/http2.c
    src/http2/hpack.c
    src/http2/hpack_primitives.c
    src/http2/huffman.c
    src/http2/bit_stream.c

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
)

set(LIB_NAME weblib)
add_library(${LIB_NAME} ${SOURCES})

configure_file(cert/cert.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(cert/key.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(config.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(${LIB_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(${LIB_NAME} PRIVATE ${OPENSSL_LIBRARIES})

pkg_check_modules(CJSON REQUIRED libcjson)
target_include_directories(${LIB_NAME} PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_libraries(${LIB_NAME} PRIVATE ${CJSON_LIBRARIES})

target_include_directories(${LIB_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${LIB_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)

set(TARGET_NAME web)
add_executable(${TARGET_NAME} src/main.c)
target_link_libraries(${TARGET_NAME} ${LIB_NAME})

add_executable(frame_test src/http2/tests/frame_test.c)
target_link_libraries(frame_test ${LIB_NAME})
target_include_directories(frame_test PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_executable(hpack_test src/http2/tests/hpack_test.c)
target_link_libraries(hpack_test ${LIB_NAME})
target_include_directories(hpack_test PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_executable(bit_stream_test src/http2/tests/bit_stream_test.c)
target_link_libraries(bit_stream_test ${LIB_NAME})
target_include_directories(bit_stream_test PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_test(NAME FrameParser COMMAND frame_test)
add_test(NAME Hpack COMMAND hpack_test)
add_test(NAME BitStream COMMAND bit_stream_test)
