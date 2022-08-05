#include <test/asserts.h>
#include <test/test_util.h>
#include <cstring/cstring.h>
//gcc -O2 -g -o testcstr testcstr.c ../test/test_util.c  ../src/cstring/cstring_util.c ../src/ctest/asserts.c -I../include -I../include/test -fsanitize=leak,address -Wall

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

void check_cstring_object(CSTRING_PTRS *cstr_ptr)
{
    size_t i=0, alignement, tmp;
    CSTRING *cstr;

    while (i<MAX_CSTRING_PTRS) {
        WARN_MSG_FMT("Checking %p at index %d.", (cstr=cstr_ptr->cstrs[i]), i)

        if (cstr==NULL) {
            WARN_MSG_FMT("cstr[%d]=NULL. Ignoring check ...", (int)i++)
            continue;
        }

        if (cstr->ctype==STRING_CONST_SELF_CONTAINED) {
            WARN_MSG_FMT(
                "Type at index %d: STRING_CONST_SELF_CONTAINED\nChecking object coerence ...",
                (int)i
            )
            C_ASSERT_TRUE(
                cstr->size>cstr->string_size,
                CTEST_SETTER(
                    CTEST_INFO(
                        "\tChecking object size cstr->size = %u is greater than string size %u ...",
                        (unsigned int)cstr->size, (unsigned int)cstr->string_size
                    ),
                    CTEST_ON_ERROR_CB(free_all_cstrs, (void *)cstr_ptr)
                )
            )

            CSTR_ALIGN(alignement, cstr->string_size)

            C_ASSERT_TRUE(
                ((alignement&(_CSTRING_ALIGN_SIZE-1))==0),
                CTEST_SETTER(
                    CTEST_INFO("\t* check alignment %u", (unsigned int)alignement),
                    CTEST_ON_ERROR_CB(free_all_cstrs, (void *)cstr_ptr)
                )
            )

            C_ASSERT_TRUE(
                alignement>cstr->string_size,
                CTEST_SETTER(
                    CTEST_INFO(
                        "\t* check alignment %u is greater than string size %u ...",
                        alignement, cstr->string_size
                    ),
                    CTEST_ON_ERROR_CB(free_all_cstrs, (void *)cstr_ptr)
                )
            )

            tmp=alignement-cstr->string_size;

            C_ASSERT_TRUE(
                (test_vector((uint8_t *)(&cstr->string[cstr->string_size]), tmp, 0)==0),
                CTEST_SETTER(
                    CTEST_INFO(
                        "\t* cheking pads with size %u has null terminated string ...",
                        (unsigned int)tmp
                    ),
                    CTEST_ON_ERROR_CB(free_all_cstrs, (void *)cstr_ptr)
                )
            )
        } else if (cstr->ctype==STRING_CONST)
            WARN_MSG_FMT(
                "Type at index %d: STRING_CONST\nIgnoring ...",
                (int)i
            )
        else if (cstr->ctype==STRING_DYNAMIC)
            WARN_MSG_FMT(
                "Type at index %d: STRING_DYNAMIC\nIgnoring ...",
                (int)i
            )
        else {
            free_all_cstrs(cstr_ptr);
            C_ASSERT_FAIL(NULL,
                CTEST_SETTER(
                    CTEST_WARN("Unknown cstr->ctype(%u)", (unsigned int)cstr->ctype)
                )
            )
        }

        ++i;
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

    check_cstring_object(&cstrings_ptr);

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
