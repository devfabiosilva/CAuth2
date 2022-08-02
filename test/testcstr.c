#include <test/asserts.h>
#include <cstring/cstring.h>
//gcc -O2 -g -o testcstr testcstr.c ../src/cstring/cstring_util.c ../src/ctest/asserts.c -I../include -I../include/test -fsanitize=leak,address -Wall
int main(int argc, char *argv[])
{
    #define MESSAGE "Tesing 123"
    #define MESSAGE_SIZE sizeof(MESSAGE)-1

    uint64_t u64;
    CSTRING *cstr=newstr(MESSAGE);
    
    C_ASSERT_NOT_NULL(
        (void *)cstr,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr is NOT NULL")
        )
    )

    u64=cstr->string_size;

    free_str(&cstr);

    C_ASSERT_NULL(
        (void *)cstr,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr is NULL")
        )
    )

    C_ASSERT_EQUAL_U64(
        MESSAGE_SIZE,
        u64
    )

    return 0;

    #undef MESSAGE_SIZE
    #undef MESSAGE
}
