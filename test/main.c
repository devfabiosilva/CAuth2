#include <cauth2.h>
#include <test/asserts.h>
//gcc -O2 test/main.c src/cauth2.c src/CyoDecode.c src/ctest/asserts.c -Iinclude -Llib -lnanocrypto1 -o test/test -fsanitize=leak,address -Wall
#define SHA1 "SHA1"
#define SHA256 "SHA256"
#define SHA512 "SHA512"

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
    {59, 94287082, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {59, 46119246, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {59, 90693936, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {1111111109, 7081804, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {1111111109, 68084774, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {1111111109, 25091201, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {1111111111, 14050471, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {1111111111, 67062674, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {1111111111, 99943326, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {1234567890, 89005924, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {1234567890, 91819424, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {1234567890, 93441116, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {2000000000, 69279037, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {2000000000, 90698825, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {2000000000, 38618901, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {20000000000, 65353130, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ, (uint8_t *)SECRET_KEY_SHA1_B32, SECRET_KEY_SHA1_B32_SZ},
    {20000000000, 77737706, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ, (uint8_t *)SECRET_KEY_SHA256_B32, SECRET_KEY_SHA256_B32_SZ},
    {20000000000, 47863826, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ, (uint8_t *)SECRET_KEY_SHA512_B32, SECRET_KEY_SHA512_B32_SZ},
    {0}
};

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

    end_tests();
    return 0;
}