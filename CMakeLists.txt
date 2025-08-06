cmake_minimum_required(VERSION 3.16)
project(web)

set(SOURCES
    src/main.c
    src/server.c
    src/stringbuilder.c
    src/server_worker.c
)

set(TARGET_NAME web)
add_executable(${TARGET_NAME} ${SOURCES})

configure_file(cert/cert.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(cert/key.pem ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(${TARGET_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_LIBRARIES})

target_include_directories(${TARGET_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${TARGET_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)
