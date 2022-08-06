#include <test/asserts.h>
#include <test/test_util.h>
#include <cstring/cstring.h>
//gcc -O2 -g -o testcstr testcstr.c ../test/test_util.c  ../src/cstring/cstring_util.c ../src/ctest/asserts.c -I../include -I../include/test -fsanitize=leak,address -Wall

#define MAX_CSTRING_PTRS (size_t)8
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

    int err;
    CSTRING_PTRS cstrings_ptr;
    CSTRING *p;

    memset((void *)&cstrings_ptr, 0, sizeof(cstrings_ptr));

#define CSTR_ADD_AND_CHECK_NEW_STR(idx, message, expected_message) \
    cstrings_ptr.cstrs[idx]=(p=newstr(message)); \
\
    C_ASSERT_NOT_NULL( \
        (void *)p, \
        CTEST_SETTER( \
            CTEST_INFO("Expecting cstr[%d] is NOT NULL", idx) \
        ) \
    ) \
\
    C_ASSERT_EQUAL_U64( \
        (uint64_t)(sizeof(message)-1), \
        (uint64_t)cstrlen(p), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
\
    C_ASSERT_EQUAL_STRING( \
        expected_message, \
        cstr_get(cstrings_ptr.cstrs[idx]), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \

    CSTR_ADD_AND_CHECK_NEW_STR(0, MESSAGE, MESSAGE)

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


#define CSTR_ADD_AND_CHECK_EMPTY_STRING(idx) \
    cstrings_ptr.cstrs[idx]=(p=newstr("")); \
\
    C_ASSERT_NOT_NULL( \
        (void *)p, \
        CTEST_SETTER( \
            CTEST_INFO("Expecting cstr[%d] is NOT NULL", idx), \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
\
    C_ASSERT_EQUAL_U64( \
        (uint64_t)0, \
        (uint64_t)cstrlen(p), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
\
    C_ASSERT_TRUE( \
        p->string[0]==0, \
        CTEST_SETTER( \
            CTEST_INFO( \
                "Check null string terminated at object %p at address %p", p,  p->string \
            ), \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    )

    CSTR_ADD_AND_CHECK_EMPTY_STRING(4)

    CSTR_ADD_AND_CHECK_EMPTY_STRING(5)

#define MESSAGE_CONCATENED_1 "This message will be concatened with"

    CSTR_ADD_AND_CHECK_NEW_STR(6, MESSAGE_CONCATENED_1, MESSAGE_CONCATENED_1)

#define MESSAGE_CONCATENED_2 "<<concatened string here :)>>"

    CSTR_ADD_AND_CHECK_NEW_STR(7, MESSAGE_CONCATENED_2, MESSAGE_CONCATENED_2)

    p=cstrings_ptr.cstrs[6];

    err=cstrconcat(&cstrings_ptr.cstrs[6], cstrings_ptr.cstrs[7]);

    C_ASSERT_NOT_NULL(
        (void *)cstrings_ptr.cstrs[6],
        CTEST_SETTER(
            CTEST_INFO("Expecting cstr[6] is NOT NULL"),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    if (p!=cstrings_ptr.cstrs[6])
        WARN_MSG_FMT("cstrconcat address changed: [old = %p] [new = %p]", p, cstrings_ptr.cstrs[6])

    p=cstrings_ptr.cstrs[6];

    C_ASSERT_TRUE(
        err==0,
        CTEST_SETTER(
            CTEST_INFO(
                "Check if expected err == 0 at index. Found err=%d",
                err
            ),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_U64(
        (uint64_t)(sizeof(MESSAGE_CONCATENED_1)+sizeof(MESSAGE_CONCATENED_2)-2),
        (uint64_t)cstrlen(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    C_ASSERT_EQUAL_STRING(
        MESSAGE_CONCATENED_1 MESSAGE_CONCATENED_2,
        cstr_get(p),
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    check_cstring_object(&cstrings_ptr);

    free_all_cstrs((void *)&cstrings_ptr);

    end_tests();

    return 0;

    #undef MESSAGE_CONCATENED_2
    #undef MESSAGE_CONCATENED_1
    #undef CSTR_ADD_AND_CHECK_EMPTY_STRING
    #undef CSTR_ADD_AND_CHECK_NEW_STR
    #undef MESSAGE_FORMAT_EXPECTED_SIZE
    #undef MESSAGE_FORMAT
    #undef MESSAGE_FORMAT_EXPECTED
    #undef MESSAGE_SIZE
    #undef MESSAGE
}

#undef MAX_CSTRING_PTRS
