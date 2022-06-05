#include <cauth2.h>
#include <test/asserts.h>
//gcc -O2 test/main.c src/cauth2.c src/CyoDecode.c src/ctest/asserts.c -Iinclude -Llib -lnanocrypto1 -o test/test -fsanitize=leak,address -Wall
#define SZ(this) sizeof(this)-1
#define SHA1 "SHA1"
#define SHA256 "SHA256"
#define SHA512 "SHA512"

#define MBEDTLS_MD_SHA1234 1234
#define SHA1234 "SHA1234"

#define SECRET_KEY_SHA1 "12345678901234567890"
#define SECRET_KEY_SHA1_SZ sizeof(SECRET_KEY_SHA1)-1
#define SECRET_KEY_SHA1_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
#define SECRET_KEY_SHA1_B32_SZ sizeof(SECRET_KEY_SHA1_B32)-1

#define SECRET_KEY_SHA256 "12345678901234567890123456789012" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA256_SZ sizeof(SECRET_KEY_SHA256)-1
#define SECRET_KEY_SHA256_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
#define SECRET_KEY_SHA256_B32_SZ sizeof(SECRET_KEY_SHA256_B32)-1

#define SECRET_KEY_SHA512 "1234567890123456789012345678901234567890123456789012345678901234" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA512_SZ sizeof(SECRET_KEY_SHA512)-1
#define SECRET_KEY_SHA512_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
#define SECRET_KEY_SHA512_B32_SZ sizeof(SECRET_KEY_SHA512_B32)-1

#define X (uint64_t)30
#define T0 (uint64_t)0

#define SET_TEST_TABLE(T, expected_totp, digit_size, alg) \
    { \
        T, expected_totp, digit_size, MBEDTLS_MD_##alg, \
        #alg, (uint8_t *)SECRET_KEY_##alg, SZ(SECRET_KEY_##alg), \
        (uint8_t *)SECRET_KEY_##alg##_B32, SZ(SECRET_KEY_##alg##_B32) \
    }

// See https://datatracker.ietf.org/doc/html/rfc6238"
struct test_table_t
{
    time_t T;
    uint32_t expected_totp;
    uint8_t digit_size;
    mbedtls_md_type_t type;
    const char *alg_name;
    uint8_t *key;
    size_t key_size;
    uint8_t *key_b32;
    size_t key_b32_size;
} TEST_TABLE[] = {
    SET_TEST_TABLE(59, 94287082, 8, SHA1),
    SET_TEST_TABLE(59, 46119246, 8, SHA256),
    SET_TEST_TABLE(59, 90693936, 8, SHA512),
    SET_TEST_TABLE(1111111109, 7081804, 8, SHA1),
    SET_TEST_TABLE(1111111109, 68084774, 8, SHA256),
    SET_TEST_TABLE(1111111109, 25091201, 8, SHA512),
    SET_TEST_TABLE(1111111111, 14050471, 8, SHA1),
    SET_TEST_TABLE(1111111111, 67062674, 8, SHA256),
    SET_TEST_TABLE(1111111111, 99943326, 8, SHA512),
    SET_TEST_TABLE(1234567890, 89005924, 8, SHA1),
    SET_TEST_TABLE(1234567890, 91819424, 8, SHA256),
    SET_TEST_TABLE(1234567890, 93441116, 8, SHA512),
    SET_TEST_TABLE(2000000000, 69279037, 8, SHA1),
    SET_TEST_TABLE(2000000000, 90698825, 8, SHA256),
    SET_TEST_TABLE(2000000000, 38618901, 8, SHA512),
    SET_TEST_TABLE(20000000000, 65353130, 8, SHA1),
    SET_TEST_TABLE(20000000000, 77737706, 8, SHA256),
    SET_TEST_TABLE(20000000000, 47863826, 8, SHA512),
    {0}
};

#undef SET_TEST_TABLE

static void
test_signatures();

static void
verify_signatures_test();

int main(int argc, char **argv) {
    int table_index=0;
    uint32_t result;
    struct test_table_t *test_table=TEST_TABLE;

    TITLE_MSG("Begin test for CAuth2. Based on https://datatracker.ietf.org/doc/html/rfc6238")
    do {

        C_ASSERT_EQUAL_INT(
            ERROR_SUCCESS,
            cauth_2fa_auth_code(
                &result, test_table->type, (uint8_t *)test_table->key, test_table->key_size,
                FALSE, T0, X, &test_table->T, test_table->digit_size
            )
        )

        C_ASSERT_EQUAL_U32(
            test_table->expected_totp, result,
            CTEST_SETTER(
                CTEST_INFO("Test table index = %d ALG NAME = \"%s\"", ++table_index, test_table->alg_name),
                CTEST_ON_SUCCESS("Expected %u -> OK", test_table->expected_totp),
                CTEST_ON_ERROR("Was expected %u but found %u", test_table->expected_totp, result)
            )
        )

        C_ASSERT_EQUAL_INT(
            ERROR_SUCCESS,
            cauth_2fa_auth_code(
                &result, test_table->type, (uint8_t *)test_table->key_b32, test_table->key_b32_size,
                TRUE, T0, X, &test_table->T, test_table->digit_size
            )
        )

        C_ASSERT_EQUAL_U32(
            test_table->expected_totp, result,
            CTEST_SETTER(
                CTEST_INFO("BASE 32 Test table index = %d ALG NAME = \"%s\"", table_index, test_table->alg_name),
                CTEST_ON_SUCCESS("Expected %u -> OK", test_table->expected_totp),
                CTEST_ON_ERROR("Was expected %u but found %u", test_table->expected_totp, result)
            )
        )
    } while ((++test_table)->alg_name);

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_DIV_ZERO,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ,
            FALSE, T0, 0, NULL, 0
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_EMPTY_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)"", 0,
            FALSE, T0, X, NULL, 0
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_DIGIT_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ,
            FALSE, T0, X, NULL, 9
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_INVALID_ALG_TYPE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1234, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ,
            FALSE, T0, X, NULL, 8
        )
    )

#define INVALID_BASE32_KEY "^Invalid~"
#define INVALID_BASE32_KEY_SIZE sizeof(INVALID_BASE32_KEY)-1
    C_ASSERT_EQUAL_INT(
        CAUTH2_2FA_BASE32_ZERO_SZ,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)INVALID_BASE32_KEY, INVALID_BASE32_KEY_SIZE,
            TRUE, T0, X, NULL, 1
        )
    )
#undef INVALID_BASE32_KEY_SIZE
#define INVALID_BASE32_KEY_SIZE

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ,
            FALSE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA512, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ,
            FALSE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ,
            TRUE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA512, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ,
            TRUE, T0, X, NULL, 8
        )
    )

    test_signatures();
    verify_signatures_test();

    end_tests();
    return 0;
}

typedef struct test_signature_t {
    const char *signatureToString;
    void *signature;
    size_t signature_size;
} TEST_SIGNATURE;

static void
cb_test_signature_util(TEST_SIGNATURE *test_signature, int is_not_error)
{
    if (test_signature->signature) {
        if (is_not_error)
            INFO_MSG_FMT("Success. Freeing \"signature\" %p of size %llu",
                test_signature->signature, (long long int)test_signature->signature_size
            )
        else
            ERROR_MSG_FMT("ERROR. Freeing \"signature\" %p of size %llu",
                test_signature->signature, (long long int)test_signature->signature_size
            )

        free(test_signature->signature);
    }

    if (test_signature->signatureToString) {
        if (is_not_error)
            INFO_MSG_FMT("Success. Freeing \"signatureToString\" %p",
                test_signature->signatureToString
            )
        else
            ERROR_MSG_FMT("ERROR. Freeing \"signature\" %p",
                test_signature->signatureToString
            )

        free((void *)test_signature->signatureToString);
    }
}

inline static void
cb_test_signatures_on_error(void *ctx)
{
    cb_test_signature_util((TEST_SIGNATURE *)ctx, 0);
}

inline static void
cb_test_signatures_on_success(void *ctx)
{
    TEST_SIGNATURE *test_signature=(TEST_SIGNATURE *)ctx;
    if ((test_signature->signatureToString=cauth_hex2str_dynamic(
        (const uint8_t *)test_signature->signature, test_signature->signature_size,
        IS_UPPER_CASE
    )))
        INFO_MSG_FMT(
            "Signature (%u) %s",
            (unsigned int)test_signature->signature_size, test_signature->signatureToString
        )
    else
        WARN_MSG("Unknown signature. Ignoring")

    cb_test_signature_util(test_signature, -1);
}

#define SIG_SHA1 ((uint8_t []){ \
    0x64, 0xFF, 0x91, 0xFF, 0x3E, 0xA1, 0xE3, 0x55, 0x7E, 0xE8, \
    0xB4, 0x48, 0x5C, 0xAA, 0xFD, 0xDE, 0x55, 0x55, 0xCA, 0xDA \
})

#define SIG_SHA256 ((uint8_t []){ \
    0x80, 0x18, 0x70, 0xe6, 0x46, 0x3e, 0x30, 0x0a, 0xd3, 0x5f, \
    0xc8, 0xfe, 0x9e, 0xc0, 0xb6, 0xbb, 0xaf, 0x98, 0x08, 0x08, \
    0x96, 0xc9, 0x4c, 0xf0, 0x45, 0x09, 0x27, 0x83, 0x63, 0xfa, \
    0x44, 0x33 \
})

#define SIG_SHA512 ((uint8_t []){ \
    0x21, 0xd2, 0x80, 0xbb, 0x01, 0x97, 0xbb, 0x86, 0x1c, 0x15, \
    0xc6, 0x0c, 0xbf, 0x46, 0x35, 0x45, 0x9c, 0xb4, 0x93, 0x69, \
    0xd1, 0x49, 0xa0, 0x76, 0x10, 0xdc, 0xe5, 0xd7, 0xfd, 0x05, \
    0x16, 0x61, 0x62, 0x1c, 0x39, 0xa4, 0x87, 0xc6, 0xd5, 0xbb, \
    0xa6, 0xd5, 0x6a, 0x90, 0x69, 0x9a, 0xfb, 0x01, 0x85, 0x3c, \
    0x37, 0xa7, 0x73, 0xc7, 0xae, 0xf7, 0x0d, 0xa8, 0x46, 0xc3, \
    0x5c, 0x3c, 0x5d, 0x3b \
})

#define SIG_SET(sg) \
{ \
  SHA##sg, \
  MBEDTLS_MD_SHA##sg, \
  SIG_SHA##sg, \
  sizeof(SIG_SHA##sg) \
}

struct test_signatures_list_t {
    const char *alg_name;
    mbedtls_md_type_t alg_type;
    uint8_t *signature;
    size_t signature_size;
} TEST_SIGNATURE_LIST[]={
    SIG_SET(1),
    SIG_SET(256),
    SIG_SET(512),
    {0}
};

#undef SIG_SET

static void
test_signatures()
{
    int err;
    TEST_SIGNATURE test_signature;
    struct test_signatures_list_t *test_signatures_list=TEST_SIGNATURE_LIST;

#define SECRET "secret goes here"
#define MESSAGE "Message goes here"

    INFO_MSG("Begin \"signature messages\" ...")

    do {

        INFO_MSG_FMT("Testing signature with algorithm: %s", test_signatures_list->alg_name)

        memset(&test_signature, 0, sizeof(test_signature));

        err=sign_message_dynamic(
            &test_signature.signature, &test_signature.signature_size,
            test_signatures_list->alg_type,
            (uint8_t *)SECRET, SZ(SECRET),
            (uint8_t *)MESSAGE, SZ(MESSAGE)
        );

        C_ASSERT_EQUAL_INT(
            ERROR_SUCCESS,
            err,
            CTEST_SETTER(
                CTEST_ON_ERROR_CB(cb_test_signatures_on_error, (void *)&test_signature)
            )
        )

        C_ASSERT_NOT_NULL(
            test_signature.signature
        )

        C_ASSERT_EQUAL_S64(
            (uint64_t)test_signatures_list->signature_size,
            (uint64_t)test_signature.signature_size,
            CTEST_SETTER(
                CTEST_ON_ERROR_CB(cb_test_signatures_on_error, (void *)&test_signature)
            )
        )

        C_ASSERT_EQUAL_BYTE(
            (uint8_t *)test_signatures_list->signature,
            (uint8_t *)test_signature.signature,
            test_signatures_list->signature_size,
            CTEST_SETTER(
                CTEST_ON_SUCCESS_CB(cb_test_signatures_on_success, (void *)&test_signature),
                CTEST_ON_ERROR_CB(cb_test_signatures_on_error, (void *)&test_signature)
            )
        )
    } while ((++test_signatures_list)->alg_name);

    INFO_MSG("End \"signature messages\"")
}

static uint8_t
*signature_hex_util(size_t *len, const char *signature)
{
    static uint8_t value[64];

    if ((*len=strlen(signature))>(2*sizeof(value))) {
        *len=0;
        return NULL;
    }

    if (cauth_str_to_hex(value, (char *)signature, *len)==0) {
        (*len)>>=1;
        return value;
    }

    *len=0;

    return NULL;
}

#define SET_VERIFY_SIGNATURE(alg, message, expected_signature, expected_success, expected_valid_signature_bool) \
{ \
    0, #alg, MBEDTLS_MD_##alg, (uint8_t *)message, expected_signature, expected_success, expected_valid_signature_bool \
}

struct verify_signatures_t {
    int index;
    const char *alg_name;
    mbedtls_md_type_t alg_type;
    uint8_t *message;
    const char *signature_expected_string;
    CAUTH_VERIFY_CODE_ERR expected_err;
    CAUTH_BOOL is_valid_signature_expected;
} VERIFY_SIGNATURES[]={
    SET_VERIFY_SIGNATURE(SHA1, "abc", "1234", CAUTH_VERIFY_WRONG_SIZE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(SHA256, "abcde", "a234", CAUTH_VERIFY_WRONG_SIZE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(SHA512, "", "a23456", CAUTH_VERIFY_SIGNATURE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(SHA512, "abcdefg", "a234", CAUTH_VERIFY_WRONG_SIZE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(SHA1234, "abcdefgh", "b234", CAUTH_VERIFY_SIGNATURE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(
        SHA1, MESSAGE,
        "64FF91FF3EA1E3557EE8B4485CAAFDDE5555CADA",
        CAUTH_VERIFY_OK, TRUE
    ),
    SET_VERIFY_SIGNATURE(
        SHA1, "a"MESSAGE,
        "64FF91FF3EA1E3557EE8B4485CAAFDDE5555CADA",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA1, MESSAGE,
        "74FF91FF3EA1E3557EE8B4485CAAFDDE5555CADA",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA256, MESSAGE,
        "801870E6463E300AD35FC8FE9EC0B6BBAF98080896C94CF04509278363FA4433",
        CAUTH_VERIFY_OK, TRUE
    ),
    SET_VERIFY_SIGNATURE(
        SHA256, "b"MESSAGE,
        "801870E6463E300AD35FC8FE9EC0B6BBAF98080896C94CF04509278363FA4433",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA256, MESSAGE,
        "801870E6463E300AD35FC8FE9EC0B6BBAF98080896C94CF04509278363FA4432",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA512, MESSAGE,
        "21D280BB0197BB861C15C60CBF4635459CB49369D149A07610DCE5D7FD051661621C39A487C6D5BBA6D56A90699AFB01853C37A773C7AEF70DA846C35C3C5D3B",
        CAUTH_VERIFY_OK, TRUE
    ),
    SET_VERIFY_SIGNATURE(
        SHA512, MESSAGE"c",
        "21D280BB0197BB861C15C60CBF4635459CB49369D149A07610DCE5D7FD051661621C39A487C6D5BBA6D56A90699AFB01853C37A773C7AEF70DA846C35C3C5D3B",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA512, MESSAGE,
        "22D280BB0197BB861C15C60CBF4635459CB49369D149A07610DCE5D7FD051661621C39A487C6D5BBA6D56A90699AFB01853C37A773C7AEF70DA846C35C3C5D3B",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    {0}
};

#undef SHA1234
#undef WRONG_TYPE_SHA1234

void
cb_verify_signatures_test_on_error(void *ctx)
{
    struct verify_signatures_t *verify_signatures=(struct verify_signatures_t *)ctx;

    ERROR_MSG_FMT(
        "\nERROR @ index %d\n\talg name %s\n\twith message: %s\n\twith expected signature: %s\n\t",
        verify_signatures->index,
        verify_signatures->alg_name,
        verify_signatures->message,
        verify_signatures->signature_expected_string
    )
}

void
cb_verify_signatures_test_on_success(void *ctx)
{
    struct verify_signatures_t *verify_signatures=(struct verify_signatures_t *)ctx;

    INFO_MSG_FMT(
        "\nSUCCESS @ index %d\n\talg name %s\n\twith message: %s\n\twith %s signature: %s\n\t",
        verify_signatures->index,
        verify_signatures->alg_name,
        verify_signatures->message,
        (verify_signatures->is_valid_signature_expected)?"expected":"unexpected",
        verify_signatures->signature_expected_string
    )
}

#define VERIFY_SIGNATURES_SIZE (int)(sizeof(VERIFY_SIGNATURES)/sizeof(VERIFY_SIGNATURES[0]))

static void
verify_signatures_test()
{
    int index=0;

    uint8_t *signature_to_be_verified;
    size_t signature_to_be_verified_size;

    struct verify_signatures_t *verify_signatures_ptr=VERIFY_SIGNATURES;

    INFO_MSG("Begin \"verify_signatures_test()\" ...\n\n")

    do {
        INFO_MSG_FMT("\nTesting index %d of %d", ++index, VERIFY_SIGNATURES_SIZE)

        signature_to_be_verified=signature_hex_util(
            &signature_to_be_verified_size,
            verify_signatures_ptr->signature_expected_string
        );

        C_ASSERT_NOT_NULL(signature_to_be_verified)

        C_ASSERT_EQUAL_INT(
            verify_signatures_ptr->expected_err,
            cauth_verify_message_with_err(
                signature_to_be_verified, signature_to_be_verified_size,
                verify_signatures_ptr->alg_type,
                (uint8_t *)SECRET, SZ(SECRET),
                verify_signatures_ptr->message, strlen((const char *)verify_signatures_ptr->message)
            ),
            CTEST_SETTER(
                CTEST_ON_ERROR_CB(cb_verify_signatures_test_on_error, (void *)verify_signatures_ptr)
            )
        )

        WARN_MSG_FMT(
            "Expecting a%s signature to pass. Conditional: TRUE",
            (verify_signatures_ptr->is_valid_signature_expected)?" valid":"n invalid"
        )

        C_ASSERT_TRUE(
            verify_signatures_ptr->is_valid_signature_expected==cauth_verify_message(
                signature_to_be_verified, signature_to_be_verified_size,
                verify_signatures_ptr->alg_type,
                (uint8_t *)SECRET, SZ(SECRET),
                verify_signatures_ptr->message, strlen((const char *)verify_signatures_ptr->message)
            ),
            CTEST_SETTER(
                CTEST_ON_SUCCESS_CB(cb_verify_signatures_test_on_success, (void *)verify_signatures_ptr),
                CTEST_ON_ERROR_CB(cb_verify_signatures_test_on_error, (void *)verify_signatures_ptr)
            )
        )

    } while ((++verify_signatures_ptr)->alg_name);

    INFO_MSG("End \"verify_signatures_test()\"")
#undef MESSAGE
#undef SECRET
}
