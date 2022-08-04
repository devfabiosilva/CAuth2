#include <test/asserts.h>
#include <cstring/cstring.h>
//gcc -O2 -g -o testcstr testcstr.c ../src/cstring/cstring_util.c ../src/ctest/asserts.c -I../include -I../include/test -fsanitize=leak,address -Wall

#define MAX_CSTRING_PTRS (size_t)4
typedef struct cstrs_t {
    CSTRING *cstrs[MAX_CSTRING_PTRS];
} CSTRING_PTRS;

static void free_all_cstrs(void *ctx)
{
    size_t i=0;
    CSTRING_PTRS *cstring_ptrs=(CSTRING_PTRS *)ctx;
    CSTRING **cstr;

    while (i<MAX_CSTRING_PTRS) {
        cstr=&cstring_ptrs->cstrs[i++];
        WARN_MSG_FMT("Index[%d]. Freeing %p (if not null)", (int)i, cstr)
        free_str(cstr);

        if (*cstr!=NULL)
            WARN_MSG_FMT("Was expected *cstr=NULL at index %d. Please fix it", (int)i)
    }

}

int main(int argc, char *argv[])
{
    #define MESSAGE "Tesing 123"
    #define MESSAGE_SIZE sizeof(MESSAGE)-1
    #define MESSAGE_FORMAT_EXPECTED "This is message with number 100 and real number 1.234 and string \"test\""
    #define MESSAGE_FORMAT "This is message with number %d and real number %0.3f and string \"%s\""
    #define MESSAGE_FORMAT_EXPECTED_SIZE sizeof(MESSAGE_FORMAT_EXPECTED)-1

    CSTRING_PTRS cstrings_ptr;
    CSTRING *p;

    memset((void *)&cstrings_ptr, 0, sizeof(cstrings_ptr));

    cstrings_ptr.cstrs[0]=(p=newstr(MESSAGE));

    C_ASSERT_NOT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr[0] is NOT NULL")
        )
    )

    C_ASSERT_EQUAL_U64(
        (uint64_t)MESSAGE_SIZE,
        (uint64_t)cstrlen(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    cstrings_ptr.cstrs[1]=(p=cstrcpy(p));

    C_ASSERT_NOT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr[1] is NOT NULL"),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_U64(
        (uint64_t)cstrlen(cstrings_ptr.cstrs[0]),
        (uint64_t)cstrlen(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_STRING(
        cstr_get(cstrings_ptr.cstrs[0]),
        cstr_get(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    cstrings_ptr.cstrs[2]=(p=newstr_fmt(MESSAGE_FORMAT, 100, 1.234, "test"));

    C_ASSERT_NOT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr[2] is NOT NULL"),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    INFO_MSG_FMT("\nFormatted message: \"%s\"\n", cstr_get(p))

    C_ASSERT_EQUAL_U64(
        (uint64_t)MESSAGE_FORMAT_EXPECTED_SIZE,
        (uint64_t)cstrlen(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    cstrings_ptr.cstrs[3]=(p=cstrcpy(p));

    C_ASSERT_NOT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr[3] is NOT NULL"),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_U64(
        (uint64_t)cstrlen(cstrings_ptr.cstrs[2]),
        (uint64_t)cstrlen(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_STRING(
        cstr_get(cstrings_ptr.cstrs[2]),
        cstr_get(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    free_all_cstrs((void *)&cstrings_ptr);

    end_tests();

    return 0;

    #undef MESSAGE_FORMAT_EXPECTED_SIZE
    #undef MESSAGE_FORMAT
    #undef MESSAGE_FORMAT_EXPECTED
    #undef MESSAGE_SIZE
    #undef MESSAGE
}

#undef MAX_CSTRING_PTRS
