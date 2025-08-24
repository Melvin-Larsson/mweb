#include "stdio.h"
#include "stdbool.h"

#define COLOR_RESET  "\x1b[0m"
#define COLOR_WHITE  "\x1b[37m"
#define COLOR_GREEN  "\x1b[32m"
#define COLOR_RED    "\x1b[31m"

#define TEST(fn) { #fn, fn }
#define ASSERT_INT_EQUAL(val1, val2) if((val1) != (val2)){ printf(COLOR_RED "[TEST FAILED] %d != %d at %d\n" COLOR_RESET, val1, val2, __LINE__); return false; }
#define ASSERT_SIZE_EQUAL(val1, val2) if((val1) != (val2)){ printf(COLOR_RED "[TEST FAILED] %zu != %zu at %d\n" COLOR_RESET, val1, val2, __LINE__); return false; }
#define ASSERT_BYTES_EQUAL(val1, size1, val2, size2) if((size1) != (size2) || memcmp(val1, val2, size1) != 0){ printf(COLOR_RED "[TEST FAILED] %s != %s\n at %d" COLOR_RESET, #val1, #val2, __LINE__); return false; }

typedef struct{
    char *name;
    bool (*run)(void);
}Test;

extern Test tests[];
extern const size_t test_count;


int main(void){
    printf("Running tests..\n");

    bool success = true;
    for(size_t i = 0; i < test_count; i++){
        Test test = tests[i];
        printf(COLOR_WHITE "[Running] %s" COLOR_RESET, test.name);
        fflush(stdout);
        bool test_status = test.run();
        printf("\r\033[K");
        if (test_status) {
            printf(COLOR_GREEN "[PASSED] %s\n" COLOR_RESET, test.name);
        } else {
            printf(COLOR_RED "[FAILED] %s\n" COLOR_RESET, test.name);
        }
        success = success && test_status;
    }

    if (success) {
        printf(COLOR_GREEN "Tests passed! \n" COLOR_RESET);
    } else {
        printf(COLOR_RED "Tests failed \n" COLOR_RESET);
    }

    return success ? 0 : 1;
}
