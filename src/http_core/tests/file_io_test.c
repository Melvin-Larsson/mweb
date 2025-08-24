#include "test_harness.h"
#include "file_io.h"
#include <string.h>

bool read(){
    bool status = file_io_init();

    file_io_read_file("config.json", (OnReadCallback){0});

    ASSERT_INT_EQUAL(true, status);
    return true;
}

Test tests[] = {
    TEST(read),
};
const size_t test_count = sizeof(tests) / sizeof(Test);

