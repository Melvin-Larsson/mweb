cmake_minimum_required(VERSION 3.16)
project(test)

set(SOURCES
    test.c
)

set(TARGET_NAME test)
add_executable(${TARGET_NAME} ${SOURCES})

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(${TARGET_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_LIBRARIES})
