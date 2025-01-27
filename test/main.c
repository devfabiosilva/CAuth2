#include <cauth2.h>
#include <asserts.h>
#include <mbedtls/md.h>
#include <test_util.h>
#include <fcntl.h>
#include <unistd.h>
#include <cauth_test.h>

static void test_rfc6238_table();
static void test_random();
static void test_totp_key();
static void test_signatures();
static void verify_signatures_test();
static void test_dummy_memory_buffer();
static void test_memory_copy_buffer();
static void test_time_const_comparator();
static void test_encode_message();
static void test_decode_message();

#define SZ(this) sizeof(this)-1
#define SHA1 "SHA1"
#define SHA256 "SHA256"
#define SHA512 "SHA512"

#define MBEDTLS_MD_SHA1234 1234
#define SHA1234 "SHA1234"

#define SECRET_KEY_SHA1 "12345678901234567890"
#define SECRET_KEY_SHA1_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

#define SECRET_KEY_SHA256 "12345678901234567890123456789012" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA256_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="

#define SECRET_KEY_SHA512 "1234567890123456789012345678901234567890123456789012345678901234" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA512_B32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="

#define X (uint64_t)30
#define T0 (uint64_t)0

#define SET_TEST_TABLE(T, expected_totp, digit_size, alg) \
    { \
        T, expected_totp, digit_size, MBEDTLS_MD_##alg, \
        #alg, (uint8_t *)SECRET_KEY_##alg, SZ(SECRET_KEY_##alg), \
        (uint8_t *)SECRET_KEY_##alg##_B32, SZ(SECRET_KEY_##alg##_B32) \
    }

// See https://datatracker.ietf.org/doc/html/rfc6238
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

int main(int argc, char **argv) {

    C_ASSERT_EQUAL_STRING("0.3.0", cauth_getVersion(), CTEST_SETTER(
      CTEST_TITLE("Check CAuth2 version is correct")
    ))
    C_ASSERT_EQUAL_STRING("202412122358", cauth_buildDate(), CTEST_SETTER(
      CTEST_TITLE("Check CAuth2 build date is correct")
    ))
    test_rfc6238_table();
    test_signatures();
    verify_signatures_test();
    test_random();
    test_totp_key();
    test_dummy_memory_buffer();
    test_memory_copy_buffer();
    test_time_const_comparator();
    test_encode_message();
    test_decode_message();
    end_tests();
    return 0;
}

static void test_rfc6238_table()
{
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
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA1, SZ(SECRET_KEY_SHA1),
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
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA1, SZ(SECRET_KEY_SHA1),
            FALSE, T0, X, NULL, 9
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_INVALID_ALG_TYPE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1234, (uint8_t *)SECRET_KEY_SHA1, SZ(SECRET_KEY_SHA1),
            FALSE, T0, X, NULL, 8
        )
    )

#define INVALID_BASE32_KEY "^Invalid~"
    C_ASSERT_EQUAL_INT(
        CAUTH2_2FA_BASE32_ZERO_SZ,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)INVALID_BASE32_KEY, SZ(INVALID_BASE32_KEY),
            TRUE, T0, X, NULL, 1
        )
    )
#define INVALID_BASE32_KEY_SIZE

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA512, SZ(SECRET_KEY_SHA512),
            FALSE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA512, (uint8_t *)SECRET_KEY_SHA1, SZ(SECRET_KEY_SHA1),
            FALSE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA1, (uint8_t *)SECRET_KEY_SHA512_B32, SZ(SECRET_KEY_SHA512_B32),
            TRUE, T0, X, NULL, 8
        )
    )

    C_ASSERT_EQUAL_INT(
        CAUTH_2FA_ERR_WRONG_KEY_SIZE,
        cauth_2fa_auth_code(
            &result, MBEDTLS_MD_SHA512, (uint8_t *)SECRET_KEY_SHA1_B32, SZ(SECRET_KEY_SHA1_B32),
            TRUE, T0, X, NULL, 8
        )
    )
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

        C_ASSERT_EQUAL_U64(
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
    SET_VERIFY_SIGNATURE(SHA1, "abc", "1234", CAUTH_VERIFY_INVALID, FALSE),
    SET_VERIFY_SIGNATURE(SHA256, "abcde", "a234", CAUTH_VERIFY_INVALID, FALSE),
    SET_VERIFY_SIGNATURE(SHA512, "", "a23456", CAUTH_VERIFY_SIGNATURE_ERR, FALSE),
    SET_VERIFY_SIGNATURE(SHA512, "abcdefg", "a234", CAUTH_VERIFY_INVALID, FALSE),
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
    SET_VERIFY_SIGNATURE(
        SHA1, MESSAGE,
        "21D280BB0197BB861C15C60CBF4635459CB49369D149A07610DCE5D7FD051661621C39A487C6D5BBA6D56A90699AFB01853C37A773C7AEF70DA846C35C3C5D3B",
        CAUTH_VERIFY_INVALID, FALSE
    ),
    SET_VERIFY_SIGNATURE(
        SHA1234, MESSAGE,
        "21D280BB0197BB861C15C60CBF4635459CB49369D149A07610DCE5D7FD051661621C39A487C6D5BBA6D56A90699AFB01853C37A773C7AEF70DA846C35C3C5D3B",
        CAUTH_VERIFY_SIGNATURE_ERR, FALSE
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

#define VERIFY_SIGNATURES_SIZE (int)(sizeof(VERIFY_SIGNATURES)/sizeof(VERIFY_SIGNATURES[0])-1)

static void
verify_signatures_test()
{
    int index=0;

    uint8_t *signature_to_be_verified;
    size_t signature_to_be_verified_size;

    struct verify_signatures_t *verify_signatures_ptr=VERIFY_SIGNATURES;

    INFO_MSG("Begin \"verify_signatures_test()\" ...\n\n")

    do {

        verify_signatures_ptr->index=++index;

        INFO_MSG_FMT("\nTesting index %d of %d", index, VERIFY_SIGNATURES_SIZE)

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

#define TEST_TYPE_NAME(type) {#type, type}
struct test_entropy_t {
  const char *name;
  uint32_t type;
} TEST_ENTROPY_TYPE[] = {
  TEST_TYPE_NAME(ENTROPY_TYPE_NOT_RECOMENDED),
  TEST_TYPE_NAME(ENTROPY_TYPE_GOOD),
  TEST_TYPE_NAME(ENTROPY_TYPE_EXCELENT),
  TEST_TYPE_NAME(ENTROPY_TYPE_PARANOIC),
  {NULL}
};
#undef TEST_TYPE_NAME

#define TEST_TYPE_NAME_SZ(type, sz) {#type, type, sz}
struct test_alg_t {
  const char *name;
  int alg;
  size_t size;
} TEST_ALG_TYPE[] = {
  TEST_TYPE_NAME_SZ(ALG_SHA1, 20),
  TEST_TYPE_NAME_SZ(ALG_SHA256, 32),
  TEST_TYPE_NAME_SZ(ALG_SHA512, 64),
  {NULL}
};

struct test_alg_t TEST_TOTP_ALG_TYPE[] = {
  TEST_TYPE_NAME_SZ(ALG_SHA1, 31),
  TEST_TYPE_NAME_SZ(ALG_SHA256, 55),
  TEST_TYPE_NAME_SZ(ALG_SHA512, 103),
  {NULL}
};

#undef TEST_TYPE_NAME_SZ

struct random_vector_t {
  uint8_t *value;
  size_t size;
};

static void test_random_destroy(void *ctx)
{
  struct random_vector_t *v = (struct random_vector_t *)ctx;

  if (v) {
    if (v->value) {
      WARN_MSG_FMT("test_random_destroy. Destroying vector %p with size %lu\n\n", v->value, v->size)
      debug_dump(v->value, v->size);
      free((void *)v->value);
    } else
      WARN_MSG("test_random_destroy null pointer. Ignoring ...\n\n")

  } else
    WARN_MSG("test_random_destroy null vector. Ignoring ...\n\n")
}

static void test_random_util(struct test_alg_t *test_alg_type, void *anyFunc) {

  int err = 0, test_number = 0;
  uint64_t wait_time;
  struct test_entropy_t *test_entropy_type_tmp;
  struct random_vector_t random_vector;

  while (test_alg_type->name) {
    test_entropy_type_tmp = TEST_ENTROPY_TYPE;
    wait_time = 1;

    while (test_entropy_type_tmp->name) {

system_entropy_ret:

      INFO_MSG_FMT("TEST %d: Testing alg %s and entropy %s with random number generator with timeout %lu s ...", ++test_number, test_alg_type->name, test_entropy_type_tmp->name, wait_time)

      if (anyFunc == (void *)generate_key_dynamic) {
        INFO_MSG_FMT("Testing generate_key_dynamic %d time(s) ...\n", test_number)
        err=generate_key_dynamic(&random_vector.value, &random_vector.size, test_alg_type->alg, test_entropy_type_tmp->type, wait_time, NULL);
      } else if (anyFunc == (void *)generate_totp_key_dynamic) {
        INFO_MSG_FMT("Testing generate_totp_key_dynamic ... %d time(s) \n", test_number)
        err=generate_totp_key_dynamic((const char **)&random_vector.value, &random_vector.size, test_alg_type->alg, test_entropy_type_tmp->type, wait_time, NULL);
      } else
        C_ASSERT_FAIL(NULL,
          CTEST_SETTER(
            CTEST_INFO("INVALID FUNCTION AT POINTER %p. Quitting ...\n", anyFunc)
          )
        )

      if (err != 0) {
        C_ASSERT_NULL(
          (void *)random_vector.value,
          CTEST_SETTER(
            CTEST_INFO("Expecting vector NULL if error is not ZERO"),
            CTEST_ON_ERROR_CB(test_random_destroy, (void *)&random_vector)
          )
        )
        if (wait_time < MAX_TIMEOUT_IN_SECOND) {
          WARN_MSG_FMT("generate_key_dynamic %s  and entropy %s error %d. Trying new timeout %lu", test_alg_type->name, test_entropy_type_tmp->name, err, ++wait_time)
          goto system_entropy_ret;
        }
        C_ASSERT_FAIL(NULL,
          CTEST_SETTER(
            CTEST_WARN("MAX_TIMEOUT_IN_SECOND %d seconds exceeded\n", MAX_TIMEOUT_IN_SECOND)
          )
        )
      }

      C_ASSERT_NOT_NULL(
        (void *)random_vector.value,
        CTEST_SETTER(
          CTEST_INFO("Expecting vector NOT NULL if error is ZERO")
        )
      )

      WARN_MSG_FMT("Vector %p with size %lu\n\n", random_vector.value, random_vector.size)
      debug_dump(random_vector.value, random_vector.size);
      debug_dump_ascii(random_vector.value, random_vector.size);

      C_ASSERT_TRUE(
        test_alg_type->size == random_vector.size,
        CTEST_SETTER(
          CTEST_INFO("Check if %s has size is %lu", test_alg_type->name, test_alg_type->size),
          CTEST_ON_SUCCESS("Expected %lu -> OK", test_alg_type->size),
          CTEST_ON_ERROR("Was expected %lu but found %lu", test_alg_type->size, random_vector.size),
          CTEST_ON_ERROR_CB(test_random_destroy, (void *)&random_vector)
        )
      )

      C_ASSERT_FALSE(
        test_vector(random_vector.value, random_vector.size, 0) == 0,
        CTEST_SETTER(
          CTEST_INFO("Check if vector %p with size %lu is NOT NULL", random_vector.value, random_vector.size),
          CTEST_ON_SUCCESS("Vector NOT NULL - OK"),
          CTEST_ON_ERROR("Was expected VECTOR NOT NULL"),
          CTEST_ON_SUCCESS_CB(test_random_destroy, (void *)&random_vector),
          CTEST_ON_ERROR_CB(test_random_destroy, (void *)&random_vector)
        )
      )

      test_entropy_type_tmp++;

    }

    test_alg_type++;

  }
}

static void test_random() {
  INFO_MSG("Begin \"test_random()\" ...\n\n")

  test_random_util(TEST_ALG_TYPE, generate_key_dynamic);

  INFO_MSG("End \"test_random()\"")
}

static void test_totp_key()
{
  INFO_MSG("Begin \"test_totp_key()\" ...\n\n")

  test_random_util(TEST_TOTP_ALG_TYPE, generate_totp_key_dynamic);

  INFO_MSG("End \"test_totp_key()\"")
}

static void test_dummy_memory_buffer()
{
    C_ASSERT_NOT_NULL(
        (void *)get_buf_cmp1_dummy(),
        CTEST_SETTER(
            CTEST_INFO("Check vector buf_cmp1_dummy is not NULL ")
        )
    )

    C_ASSERT_NOT_NULL(
        (void *)get_buf_cmp2_dummy(),
        CTEST_SETTER(
            CTEST_INFO("Check vector buf_cmp2_dummy is not NULL ")
        )
    )

#define CORRECT_VECTOR_SIZE (size_t)72
    C_ASSERT_TRUE(
        get_buf_cmp1_dummy_size() == CORRECT_VECTOR_SIZE,
        CTEST_SETTER(
            CTEST_INFO("Check buf_cmp1_dummy size is %lu", CORRECT_VECTOR_SIZE)
        )
    )

    C_ASSERT_TRUE(
        get_buf_cmp2_dummy_size() == CORRECT_VECTOR_SIZE,
        CTEST_SETTER(
            CTEST_INFO("Check buf_cmp2_dummy size is %lu", CORRECT_VECTOR_SIZE)
        )
    )
#undef CORRECT_VECTOR_SIZE

    C_ASSERT_TRUE(
        (test_vector((uint8_t *)get_buf_cmp1_dummy(), get_buf_cmp1_dummy_size(), 0xF0) == 0),
        CTEST_SETTER(
            CTEST_INFO("Check buf_cmp1_dummy is filled with 0xF0 value ...")
        )
    )

    C_ASSERT_TRUE(
        (test_vector((uint8_t *)get_buf_cmp2_dummy(), get_buf_cmp2_dummy_size(), 0x0A) == 0),
        CTEST_SETTER(
            CTEST_INFO("Check buf_cmp2_dummy is filled with 0x0A value ...")
        )
    )
}

#define SET_MEMORY_VECTOR(val, val_expected)\
 { val, sizeof(val)/sizeof(uint8_t), val_expected, sizeof(val_expected)/sizeof(uint8_t) }

#define NULL_POINTER NULL, 0
#define VEC(v) (uint8_t *)v, sizeof(v)
static uint8_t ZERO_VEC[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
_Static_assert(sizeof(ZERO_VEC) == 16, "ZERO_VEC must have size 16 bytes");

struct memory_copy_test_t {
  const uint8_t *src;
  size_t src_sz;
  const uint8_t *expected_dest;
  size_t expected_dest_sz;
} MEMORY_COPY_TEST [] = {
  SET_MEMORY_VECTOR(((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8}), ((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0})),
  SET_MEMORY_VECTOR(((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), ((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})),
  SET_MEMORY_VECTOR(((uint8_t []){0, 0, 0, 0, 0, 0, 0, 0}), ZERO_VEC),
  SET_MEMORY_VECTOR(((uint8_t []){0, 0, 0, 0, 1, 0, 0, 0}), ((uint8_t []){0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
  SET_MEMORY_VECTOR(((uint8_t []){10, 11}), ((uint8_t []){10, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
  {NULL_POINTER, VEC(ZERO_VEC)},
  {NULL}
};

#undef SET_MEMORY_VECTOR

#define COMPARE_VECTOR(a, b) \
  is_vec_content_eq((uint8_t *)a, a##_sz, b, b##_sz)

static void test_memory_copy_buffer()
{
  int i = 0;
  struct memory_copy_test_t *memory_copy_test = MEMORY_COPY_TEST;
  uint8_t dest_vec[16];
  size_t dest_vec_sz = sizeof(dest_vec);
  INFO_MSG("Testing Memory copy buffer...")

  while (memory_copy_test->expected_dest) {
    INFO_MSG_FMT("Testing %d vector %p with size %lu ...\n", ++i, memory_copy_test->src, memory_copy_test->src_sz)

    C_ASSERT_TRUE(
      dest_vec_sz >= memory_copy_test->src_sz,
      CTEST_SETTER(
        CTEST_INFO("Check %d dest_vec_sz %lu is equal or greater than memory vector size %lu\n", i, dest_vec_sz, memory_copy_test->src_sz)
      )
    )

    memset(dest_vec, 0x0f, dest_vec_sz);
    debug_dump((uint8_t *)memory_copy_test->src, memory_copy_test->src_sz);
    INFO_MSG_FMT("Expected vector %p with size %lu ...\n", memory_copy_test->expected_dest, memory_copy_test->expected_dest_sz)
    debug_dump((uint8_t *)memory_copy_test->expected_dest, memory_copy_test->expected_dest_sz);

    memcpy_max(dest_vec, (uint8_t *)memory_copy_test->src, memory_copy_test->src_sz, dest_vec_sz);

    INFO_MSG_FMT("Result vector %p with size %lu ...\n", dest_vec, dest_vec_sz)
    debug_dump((uint8_t *)dest_vec, dest_vec_sz);
    C_ASSERT_TRUE(
      COMPARE_VECTOR(memory_copy_test->expected_dest, dest_vec),
      CTEST_SETTER(
        CTEST_INFO("Check test %d equal memory vector\n", i)
      )
    )
    ++memory_copy_test;
  };
}

#define SET_TIME_CONST_COMPARE(val1, val2, expected)\
 { val1, sizeof(val1)/sizeof(uint8_t), val2, sizeof(val2)/sizeof(uint8_t), expected }

struct time_const_compare_test_t {
  const uint8_t *cmp1;
  size_t cmp1_sz;
  const uint8_t *cmp2;
  size_t cmp2_sz;
  bool expected_value;
} TIME_CONST_COMPARE_TEST [] = {
  SET_TIME_CONST_COMPARE(((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8}), ((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 0}), false),
  SET_TIME_CONST_COMPARE(((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), ((uint8_t []){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), true),
  SET_TIME_CONST_COMPARE(((uint8_t []){0, 0, 0, 0, 0, 0, 0, 0}), ((uint8_t []){0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), false),
  SET_TIME_CONST_COMPARE(((uint8_t []){0, 0, 0, 0, 1, 0, 0, 0}), ((uint8_t []){0, 0, 0, 0, 1, 0, 0, 0}), true),
  SET_TIME_CONST_COMPARE(((uint8_t []){10, 11}), ((uint8_t []){10, 11}), true),
  SET_TIME_CONST_COMPARE(
    ((uint8_t [])
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72}),
    ((uint8_t [])
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72}),
     true),
  SET_TIME_CONST_COMPARE(
    ((uint8_t [])
      {1, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72}),
    ((uint8_t [])
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72}),
     false),
  SET_TIME_CONST_COMPARE(
    ((uint8_t [])
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73}),
    ((uint8_t [])
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73}),
     false),
  {NULL}
};

static void test_time_const_comparator()
{
  int i = 0;
  struct time_const_compare_test_t *time_const_compare_test = TIME_CONST_COMPARE_TEST;

  INFO_MSG("Testing time constant comparator ...")

  while (time_const_compare_test->cmp1) {
    INFO_MSG_FMT("Testing %d time constant comparator cmp1= %p with size %lu and cmp2 %p with size %lu is %s ...\n", ++i,
      time_const_compare_test->cmp1, time_const_compare_test->cmp1_sz, time_const_compare_test->cmp2, time_const_compare_test->cmp2_sz,
      time_const_compare_test->expected_value?"TRUE":"FALSE")

    INFO_MSG_FMT("cmp1 vector %p with size %lu ...\n", time_const_compare_test->cmp1, time_const_compare_test->cmp1_sz)
    debug_dump((uint8_t *)time_const_compare_test->cmp1, time_const_compare_test->cmp1_sz);

    INFO_MSG_FMT("cmp2 vector %p with size %lu ...\n", time_const_compare_test->cmp2, time_const_compare_test->cmp2_sz)
    debug_dump((uint8_t *)time_const_compare_test->cmp2, time_const_compare_test->cmp2_sz);

    C_ASSERT_TRUE(
       time_const_compare_test->expected_value == time_const_compare(
        (uint8_t *)time_const_compare_test->cmp1, time_const_compare_test->cmp1_sz, (uint8_t *)time_const_compare_test->cmp2, time_const_compare_test->cmp2_sz),
      CTEST_SETTER(
        CTEST_INFO("Check time_const_compare returns %s\n", time_const_compare_test->expected_value?"TRUE":"FALSE")
      )
    )

    ++time_const_compare_test;
  };
}

#define SET_ENCODE_EXPECTED(message, expected_encoded_message, expected_err, alg) \
{(uint8_t *)message, sizeof(message) - 1, (const char *)expected_encoded_message, expected_err, alg, sizeof(expected_encoded_message) - 1},

struct encode_expected_t {
  uint8_t *message;
  size_t message_len;
  const char *expected_encoded_message;
  int expected_err;
  int alg;
  size_t expected_encoded_size;
} ENCODE_EXPECTED[] = {
  SET_ENCODE_EXPECTED("12345678901234567890", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 0, ALG_SHA1)
  SET_ENCODE_EXPECTED("12345678901234567890123456789012",
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====",
    0,
    ALG_SHA256
  )
  SET_ENCODE_EXPECTED(
    "1234567890123456789012345678901212345678901234567890123456789012",
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYDCMQ=",
    0,
    ALG_SHA512
  )
  SET_ENCODE_EXPECTED("1234", "", 901, ALG_SHA1)
  SET_ENCODE_EXPECTED("123456789",
    "",
    901,
    ALG_SHA256
  )
  SET_ENCODE_EXPECTED(
    "123456789012345678901234",
    "",
    901,
    ALG_SHA512
  )
  {NULL, 0, NULL, 0, 0, 0}
};

#undef SET_ENCODE_EXPECTED

static void test_encode_message()
{
  int err;
  const char *out;
  size_t out_len;
  struct encode_expected_t *encode_expected = ENCODE_EXPECTED;

  while (encode_expected->message) {
    err = encode_totp_key_with_alg_check_dynamic(&out, &out_len, encode_expected->alg, encode_expected->message, encode_expected->message_len);

    if (err == 0) {
      C_ASSERT_NOT_NULL((void *)out)
      C_ASSERT_EQUAL_STRING((char *)encode_expected->expected_encoded_message, (char *)out,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      C_ASSERT_EQUAL_LONG_INT((long int)encode_expected->expected_encoded_size, (long int)out_len,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      free((void *)out);
    } else {
      C_ASSERT_NULL((void *)out,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      C_ASSERT_EQUAL_INT(0, out_len)
      C_ASSERT_TRUE(encode_expected->expected_err == err)
    }

    ++encode_expected;
  }
}

#define SET_DECODE_EXPECTED(message, expected_encoded_message, expected_err, alg) \
{(const char *)message, sizeof(message) - 1, (uint8_t *)expected_encoded_message, expected_err, alg, sizeof(expected_encoded_message) - 1},

struct decode_expected_t {
  const char *message;
  size_t message_len;
  uint8_t *expected_decoded_message;
  int expected_err;
  int alg;
  size_t expected_decoded_size;
} DECODE_EXPECTED[] = {
  SET_DECODE_EXPECTED("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "12345678901234567890", 0, ALG_SHA1)
  SET_DECODE_EXPECTED("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====", "12345678901234567890123456789012",
    0,
    ALG_SHA256
  )
  SET_DECODE_EXPECTED(
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYDCMQ=",
    "1234567890123456789012345678901212345678901234567890123456789012",
    0,
    ALG_SHA512
  )
  SET_DECODE_EXPECTED("1234", "", 750, ALG_SHA1)
  SET_DECODE_EXPECTED("123456789",
    "",
    750,
    ALG_SHA256
  )
  SET_DECODE_EXPECTED(
    "123456789012345678901234",
    "",
    752,
    ALG_SHA512
  )
  {NULL, 0, NULL, 0, 0, 0}
};

#undef SET_DECODE_EXPECTED

static void test_decode_message()
{
  int err, i = 0;
  uint8_t *out;
  size_t out_len;
  struct decode_expected_t *decode_expected = DECODE_EXPECTED;

  while (decode_expected->message) {
    err = decode_totp_key_with_alg_check_dynamic(&out, &out_len, decode_expected->alg, decode_expected->message, decode_expected->message_len);
    i++;
    if (err == 0) {
      C_ASSERT_NOT_NULL((void *)out)
      C_ASSERT_EQUAL_LONG_INT((long int)decode_expected->expected_decoded_size, (long int)out_len,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      C_ASSERT_EQUAL_BYTE((uint8_t *)decode_expected->expected_decoded_message, (uint8_t *)out, decode_expected->expected_decoded_size,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      free((void *)out);
    } else {
      C_ASSERT_NULL((void *)out,
        CTEST_SETTER(
          CTEST_ON_ERROR_CB(free, (void *)out)
        )
      )
      C_ASSERT_EQUAL_INT(0, out_len)
      C_ASSERT_TRUE(decode_expected->expected_err == err)
    }

    ++decode_expected;
  }
}

