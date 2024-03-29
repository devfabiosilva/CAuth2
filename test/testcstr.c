#define _GNU_SOURCE
#include <stdio.h>
#include <test/asserts.h>
#include <test/test_util.h>
#include <cstring/cstring.h>
//gcc -O2 -g -o testcstr testcstr.c ../test/test_util.c  ../src/cstring/cstring_util.c ../src/ctest/asserts.c -I../include -I../include/test -fsanitize=leak,address -Wall

#define MAX_CSTRING_PTRS (size_t)12
typedef struct cstrs_t {
    CSTRING *cstrs[MAX_CSTRING_PTRS];
} CSTRING_PTRS;

static void free_all_cstrs(void *ctx)
{
    size_t i=0;
    CSTRING_PTRS *cstring_ptrs=(CSTRING_PTRS *)ctx;
    CSTRING **cstr;

    while (i<MAX_CSTRING_PTRS) {
        cstr=&cstring_ptrs->cstrs[i];
        WARN_MSG_FMT("Index[%d]. Freeing %p (if not null)", (int)i, cstr)
        free_str(cstr);

        if (*cstr!=NULL)
            WARN_MSG_FMT("Was expected *cstr=NULL at index %d. Please fix it", (int)i)
        ++i;
    }

}

void check_cstring_object(CSTRING_PTRS *cstr_ptr)
{
    size_t i=0, alignement, tmp;
    int32_t ctype;
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
            ctype=cstr->ctype;

            free_all_cstrs(cstr_ptr);
            C_ASSERT_FAIL(NULL,
                CTEST_SETTER(
                    CTEST_WARN("Unknown cstr->ctype(%u)", (unsigned int)ctype)
                )
            )
        }

        ++i;
    }
}

static
void testcstr_array_free(void *ctx)
{
    CSTRING_ARRAY *a=(CSTRING_ARRAY *)ctx;

    if (a!=NULL)
        INFO_MSG_FMT(
            "OBJECT INFO:\n\tAddress: %p\n\tNumber of elements: %d\n\t"\
            "Total string size: %lu\n\tTotal objects size: %lu\n\tTotal Size: %lu\n",
            a, cstring_array_num_elements(a),
            (unsigned long int)cstring_array_total_string_size(a), (unsigned long int)cstring_array_total_objects_size(a),
            (unsigned long int)cstring_array_total_size(a)
        )
    else
        WARN_MSG("Was expected ctx!=NULL. Please. Fix it")

    free_cstring_array(&a);

    if (a!=NULL)
        WARN_MSG_FMT("Was expected a=NULL but found %p. Please. Fix it", a)
}

static
void testcstr_index_element_helper(void *ctx)
{
    typedef CSTRING *(*f)(CSTRING_ARRAY *);

    int i;
    const char 
        *str,
        *expected,
        *msg_tmp="first";

    CSTRING_ARRAY *a=(CSTRING_ARRAY *)ctx;
    CSTRING *p;

    f h;

    WARN_MSG("Begin index element test ...")

    p=cstring_array_previous(a);

    C_ASSERT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Check if previous is NULL"),
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

#define CHECK_INDEX 10

_Static_assert(CHECK_INDEX<=CONST_STR_TEST_ELEMENTS, "ERROR. CHECK_INDEX > CONST_STR_TEST_ELEMENTS");

    for (i=0;i<CHECK_INDEX;i++) {
        p=cstring_array_next(a);

#undef CHECK_INDEX

        C_ASSERT_NOT_NULL(
            (void *)p,
            CTEST_SETTER(
                CTEST_INFO("Check if next (%p) at index %i is NOT NULL", p, i),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        str=cstr_get(p);

        C_ASSERT_EQUAL_STRING(
            CONST_STR_TEST[i],
            str,
            CTEST_SETTER(
                CTEST_INFO(
                    "Check if next CSTRING[%d] at pointer (%p) with string at (%p) is equal to CONST_STR_TEST[%i]",
                    i, p, str, i
                ),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )
    }

    i=0;
    expected=CONST_STR_TEST[0];
    h=cstring_array_first;

testcstr_index_element_helper_START:
    p=h(a);

    C_ASSERT_NOT_NULL(
        (void *)p,
        CTEST_SETTER(
            CTEST_INFO("Check if %s index (%p) at index %d is NOT NULL", msg_tmp, p, i),
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    str=cstr_get(p);

    C_ASSERT_EQUAL_STRING(
        expected,
        str,
        CTEST_SETTER(
            CTEST_INFO(
                "Check if %s CSTRING[%d] at pointer (%p) with string at (%p) is equal to CONST_STR_TEST[0]",
                msg_tmp, i, p, str
            ),
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    if (h!=cstring_array_last) {
        i=(int)CONST_STR_TEST_ELEMENTS_LAST_ELEMENT;
        expected=CONST_STR_TEST_3[CONST_STR_TEST_ELEMENTS_3_LAST_INDEX];
        h=cstring_array_last;
        goto testcstr_index_element_helper_START;
    }

    testcstr_array_free((void *)a);
    WARN_MSG("End index element test ...")
}

static
void testcstr_array_index_next_previous_helper(void *ctx)
{

    typedef CSTRING *(*f)(CSTRING_ARRAY *);

    int i;
    int32_t s32_tmp;
    const char *str, *msg_tmp="next";
    f h=cstring_array_next;
    CSTRING_ARRAY *a=(CSTRING_ARRAY *)ctx;
    CSTRING *p;

testcstr_array_index_next_previous_helper_START:

    i=0;

    WARN_MSG_FMT("Begin test (%s and index)", msg_tmp)

    while ((p=h(a))) {
        WARN_MSG_FMT("Test %s array at index %d at (%p)", msg_tmp, i, p)

        str=cstr_get(p);

        C_ASSERT_NOT_NULL(
            (void *)str,
            CTEST_SETTER(
                CTEST_INFO("Check if string pointer (%p) at index %d is NOT null ...", str, i),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        INFO_MSG_FMT("Test[%d] at (%p) is \"%s\"", i, str, str)

        ++i;
    }

    s32_tmp=cstring_array_num_elements(a);

    C_ASSERT_EQUAL_S32(
        i,
        s32_tmp,
        CTEST_SETTER(
            CTEST_INFO("Check %s function has reached all elements ... ([scan: %d] == [number of elements: %d])", msg_tmp, i, s32_tmp),
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    if (h==cstring_array_next) {
        h=cstring_array_previous;
        msg_tmp="previous";
        goto testcstr_array_index_next_previous_helper_START;
    }

    //testcstr_array_free((void *)a);
    testcstr_index_element_helper((void *)a);
    WARN_MSG("End test (Next, Previous and Index)")
}

static
void testcstr_array()
{
    int res;
    CSTRING *p;
    CSTRING_ARRAY *a, *a_old;
    size_t t=0;
    int32_t s32_tmp;
    char *msg;

    WARN_MSG("Begin TEST CSTRING ARRAY")

    a=new_cstring_array();

    C_ASSERT_NOT_NULL(
        (void *)a,
        CTEST_SETTER(
            CTEST_INFO("Expecting new_cstring_array is NOT NULL")
        )
    )

    for(t=0;t<CONST_STR_TEST_ELEMENTS;t++) {
        p=newstr(CONST_STR_TEST[t]);

        C_ASSERT_NOT_NULL(
            (void *)p,
            CTEST_SETTER(
                CTEST_INFO("Check newstr[%d]=(%p) is NOT NULL", (unsigned int)t, p),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        a_old=a;

        res=c_add_string_to_array(&a, p);

        C_ASSERT_TRUE(
            res==0,
            CTEST_SETTER(
                CTEST_INFO(
                    "Check array string has add the item %d at %p into %p with text message \"%.*s\".",
                    (unsigned int)t, p, a, cstrlen(p), cstr_get(p)
                ),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        if (a!=a_old)
            WARN_MSG_FMT("WARNING: Array address has changed [new = %p] [old = %p]", a, a_old);

        WARN_MSG_FMT("Text \"%s\" added", cstr_get(cstring_array_index(a, (int32_t)t)))
    }

    s32_tmp=cstring_array_num_elements(a);

    C_ASSERT_EQUAL_S32(
        (int32_t)CONST_STR_TEST_ELEMENTS,
        s32_tmp,
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    for(t=CONST_STR_TEST_ELEMENTS;t<(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2);t++) {

        p=newstrconst(CONST_STR_TEST_2[t-CONST_STR_TEST_ELEMENTS]);

        C_ASSERT_NOT_NULL(
            (void *)p,
            CTEST_SETTER(
                CTEST_INFO("Check (const) newstr[%d]=(%p) is NOT NULL", (unsigned int)t, p),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        a_old=a;

        res=c_add_string_to_array(&a, p);

        C_ASSERT_TRUE(
            res==0,
            CTEST_SETTER(
                CTEST_INFO(
                    "Check array string has add the item const %d at %p into %p with text message \"%.*s\".",
                    (unsigned int)t, p, a, cstrlen(p), cstr_get(p)
                ),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        if (a!=a_old)
            WARN_MSG_FMT("WARNING step 2: Array address has changed [new = %p] [old = %p]", a, a_old);

        WARN_MSG_FMT("Text const \"%s\" added", cstr_get(cstring_array_index(a, (int32_t)t)))
    }

    s32_tmp=cstring_array_num_elements(a);

    C_ASSERT_EQUAL_S32(
        (int32_t)(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2),
        s32_tmp,
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    for(t=(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2);t<(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2+CONST_STR_TEST_ELEMENTS_3);t++) {

        s32_tmp=asprintf(&msg, "%s", CONST_STR_TEST_3[t-(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2)]);

        C_ASSERT_TRUE(
            s32_tmp>-1,
            CTEST_SETTER(
                CTEST_INFO(
                    "Check if message pointer at index %u has been allocated with valid size",
                    (unsigned int)t
                ),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        if ((p=anewstr((const char *)msg))==NULL) {
            WARN_MSG_FMT(
                "Test fail. Exiting and free %u bytes at %p at index %u",
                (unsigned int)(s32_tmp+1), msg, (unsigned int)t
            )

            free(msg);
        }

        C_ASSERT_NOT_NULL(
            (void *)p,
            CTEST_SETTER(
                CTEST_INFO("Check (dyn) newstr[%d]=(%p) is NOT NULL", (unsigned int)t, p),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        a_old=a;

        res=c_add_string_to_array(&a, p);

        C_ASSERT_TRUE(
            res==0,
            CTEST_SETTER(
                CTEST_INFO(
                    "Check array string has add the item dyn %d at %p into %p with text message \"%.*s\".",
                    (unsigned int)t, p, a, cstrlen(p), cstr_get(p)
                ),
                CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
            )
        )

        if (a!=a_old)
            WARN_MSG_FMT("WARNING step 3: Array address has changed [new = %p] [old = %p]", a, a_old);

        WARN_MSG_FMT("Text const \"%s\" added", cstr_get(cstring_array_index(a, (int32_t)t)))
    }

    s32_tmp=cstring_array_num_elements(a);

    C_ASSERT_EQUAL_S32(
        (int32_t)(CONST_STR_TEST_ELEMENTS+CONST_STR_TEST_ELEMENTS_2+CONST_STR_TEST_ELEMENTS_3),
        s32_tmp,
        CTEST_SETTER(
            CTEST_ON_ERROR_CB(testcstr_array_free, (void *)a)
        )
    )

    testcstr_array_index_next_previous_helper((void *)a);
    WARN_MSG("End TEST CSTRING ARRAY")
}

int main(int argc, char *argv[])
{
    #define MESSAGE "Tesing 123"
    #define MESSAGE_SIZE sizeof(MESSAGE)-1
    #define MESSAGE_FORMAT_EXPECTED "This is message with number 100 and real number 1.234 and string \"test\""
    #define MESSAGE_FORMAT "This is message with number %d and real number %0.3f and string \"%s\""
    #define MESSAGE_FORMAT_EXPECTED_SIZE sizeof(MESSAGE_FORMAT_EXPECTED)-1

    int err;
    char *charptr;
    CSTRING_PTRS cstrings_ptr;
    CSTRING *p;

    memset((void *)&cstrings_ptr, 0, sizeof(cstrings_ptr));

#define CSTR_ADD_AND_CHECK_NEW_STR_UTIL(idx, message, expected_message) \
    C_ASSERT_NOT_NULL( \
        (void *)p, \
        CTEST_SETTER( \
            CTEST_INFO("Expecting cstr[%d] is NOT NULL", idx) \
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
    C_ASSERT_EQUAL_U64( \
        (uint64_t)(sizeof(message)-1), \
        (uint64_t)cstrlen(p), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \

#define CSTR_ADD_AND_CHECK_NEW_STR(idx, message, expected_message) \
    cstrings_ptr.cstrs[idx]=(p=newstr(message)); \
    CSTR_ADD_AND_CHECK_NEW_STR_UTIL(idx, message, expected_message)

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

#define CSTR_ADD_AND_CHECK_CONCATENED(idx1, idx2, message1, message2, must_have_same_pointer) \
    p=cstrings_ptr.cstrs[idx1]; \
\
    err=cstrconcat(&cstrings_ptr.cstrs[idx1], cstrings_ptr.cstrs[idx2]); \
\
    C_ASSERT_NOT_NULL( \
        (void *)cstrings_ptr.cstrs[idx1], \
        CTEST_SETTER( \
            CTEST_INFO("Expecting cstr[%d] is NOT NULL", idx1), \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
\
    if (p!=cstrings_ptr.cstrs[idx1]) \
        WARN_MSG_FMT("cstrconcat address changed: [old = %p] [new = %p]", p, cstrings_ptr.cstrs[idx1]) \
\
    if (must_have_same_pointer) \
        C_ASSERT_TRUE( \
            (p==cstrings_ptr.cstrs[idx1]), \
            CTEST_SETTER( \
                CTEST_INFO( \
                    "It MUST have same pointer. Checking if is TRUE" \
                ), \
                CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
            ) \
        ) \
\
    p=cstrings_ptr.cstrs[idx1]; \
\
    C_ASSERT_TRUE( \
        err==0, \
        CTEST_SETTER( \
            CTEST_INFO( \
                "Check if expected err == 0 at index. Found err=%d", \
                err \
            ), \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
\
    C_ASSERT_EQUAL_STRING( \
        message1 message2, \
        cstr_get(p), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    ) \
    C_ASSERT_EQUAL_U64( \
        (uint64_t)(sizeof(message1)+sizeof(message2)-2), \
        (uint64_t)cstrlen(p), \
        CTEST_SETTER( \
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr) \
        ) \
    )

    CSTR_ADD_AND_CHECK_CONCATENED(6, 7, MESSAGE_CONCATENED_1, MESSAGE_CONCATENED_2, C_TEST_FALSE)

    CSTR_ADD_AND_CHECK_CONCATENED(4, 5, "", "", C_TEST_TRUE)

    CSTR_ADD_AND_CHECK_CONCATENED(4, 1, "", MESSAGE, C_TEST_FALSE)

    CSTR_ADD_AND_CHECK_CONCATENED(4, 5, MESSAGE, "", C_TEST_TRUE)

    CSTR_ADD_AND_CHECK_CONCATENED(4, 4, MESSAGE, MESSAGE, C_TEST_FALSE)

    CSTR_ADD_AND_CHECK_CONCATENED(2, 5, MESSAGE_FORMAT_EXPECTED, "", C_TEST_TRUE)

    CSTR_ADD_AND_CHECK_CONCATENED(2, 6, MESSAGE_FORMAT_EXPECTED, MESSAGE_CONCATENED_1 MESSAGE_CONCATENED_2, C_TEST_FALSE)

#define CSTR_ADD_AND_CHECK_NEW_STR_DYN(idx, message_ptr, message, expected_message) \
    cstrings_ptr.cstrs[idx]=(p=anewstr(message_ptr)); \
    CSTR_ADD_AND_CHECK_NEW_STR_UTIL(idx, message, expected_message)

#define NEW_ALLOC_STRING "New string allocated dynamically"

    C_ASSERT_TRUE(
        (asprintf(&charptr, "%s", NEW_ALLOC_STRING)>-1),
        CTEST_SETTER(
            CTEST_INFO(
                "Check if new string is allocated dynamically in memory ..."
            ),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    CSTR_ADD_AND_CHECK_NEW_STR_DYN(8, charptr, NEW_ALLOC_STRING, NEW_ALLOC_STRING)

#define CSTR_ADD_AND_CHECK_NEW_STR_CONST(idx, message, expected_message) \
    cstrings_ptr.cstrs[idx]=(p=newstrconst(message)); \
    CSTR_ADD_AND_CHECK_NEW_STR_UTIL(idx, message, expected_message)

#define NEW_CONST_STRING "New const string added"

    CSTR_ADD_AND_CHECK_NEW_STR_CONST(9, NEW_CONST_STRING, NEW_CONST_STRING)

#define NEW_CONST_STRING_2 "Second new const string added"
    CSTR_ADD_AND_CHECK_NEW_STR_CONST(10, NEW_CONST_STRING_2, NEW_CONST_STRING_2)

    CSTR_ADD_AND_CHECK_CONCATENED(10, 10, NEW_CONST_STRING_2, NEW_CONST_STRING_2, C_TEST_FALSE)

    CSTR_ADD_AND_CHECK_CONCATENED(10, 9, NEW_CONST_STRING_2 NEW_CONST_STRING_2, NEW_CONST_STRING, C_TEST_FALSE)

#define NEW_ALLOC_STRING_2 "New string allocated dynamically"

    C_ASSERT_TRUE(
        (asprintf(&charptr, "%s", NEW_ALLOC_STRING_2)>-1),
        CTEST_SETTER(
            CTEST_INFO(
                "Check if new string is allocated dynamically in memory (second allocation)..."
            ),
            CTEST_ON_ERROR_CB(free_all_cstrs, (void *)&cstrings_ptr)
        )
    )

    CSTR_ADD_AND_CHECK_NEW_STR_DYN(11, charptr, NEW_ALLOC_STRING_2, NEW_ALLOC_STRING_2)

    CSTR_ADD_AND_CHECK_CONCATENED(11, 9, NEW_ALLOC_STRING_2, NEW_CONST_STRING, C_TEST_FALSE)

    check_cstring_object(&cstrings_ptr);

    free_all_cstrs((void *)&cstrings_ptr);

    testcstr_array();

    end_tests();

    return 0;

    #undef NEW_ALLOC_STRING_2
    #undef NEW_CONST_STRING_2
    #undef NEW_CONST_STRING
    #undef CSTR_ADD_AND_CHECK_NEW_STR_CONST
    #undef NEW_ALLOC_STRING
    #undef CSTR_ADD_AND_CHECK_NEW_STR_DYN
    #undef CSTR_ADD_AND_CHECK_CONCATENED
    #undef MESSAGE_CONCATENED_2
    #undef MESSAGE_CONCATENED_1
    #undef CSTR_ADD_AND_CHECK_EMPTY_STRING
    #undef CSTR_ADD_AND_CHECK_NEW_STR
    #undef CSTR_ADD_AND_CHECK_NEW_STR_UTIL
    #undef MESSAGE_FORMAT_EXPECTED_SIZE
    #undef MESSAGE_FORMAT
    #undef MESSAGE_FORMAT_EXPECTED
    #undef MESSAGE_SIZE
    #undef MESSAGE
}

#undef MAX_CSTRING_PTRS
