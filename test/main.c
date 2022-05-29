#include <cauth2.h>
#include <test/asserts.h>
//gcc -O2 test/main.c src/cauth2.c src/CyoDecode.c src/ctest/asserts.c -Iinclude -Llib -lnanocrypto1 -o test/test -fsanitize=leak,address -Wall
#define SHA1 "SHA1"
#define SHA256 "SHA256"
#define SHA512 "SHA512"

#define SECRET_KEY_SHA1 "12345678901234567890"
#define SECRET_KEY_SHA1_SZ sizeof(SECRET_KEY_SHA1)-1

#define SECRET_KEY_SHA256 "12345678901234567890123456789012" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA256_SZ sizeof(SECRET_KEY_SHA256)-1

#define SECRET_KEY_SHA512 "1234567890123456789012345678901234567890123456789012345678901234" // see https://www.rfc-editor.org/errata_search.php?rfc=6238&rec_status=0
#define SECRET_KEY_SHA512_SZ sizeof(SECRET_KEY_SHA512)-1

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
} TEST_TABLE[] = {
    {59, 94287082, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {59, 46119246, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {59, 90693936, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {1111111109, 7081804, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {1111111109, 68084774, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {1111111109, 25091201, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {1111111111, 14050471, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {1111111111, 67062674, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {1111111111, 99943326, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {1234567890, 89005924, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {1234567890, 91819424, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {1234567890, 93441116, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {2000000000, 69279037, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {2000000000, 90698825, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {2000000000, 38618901, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {20000000000, 65353130, 8, MBEDTLS_MD_SHA1, SHA1, (uint8_t *)SECRET_KEY_SHA1, SECRET_KEY_SHA1_SZ},
    {20000000000, 77737706, 8, MBEDTLS_MD_SHA256, SHA256, (uint8_t *)SECRET_KEY_SHA256, SECRET_KEY_SHA256_SZ},
    {20000000000, 47863826, 8, MBEDTLS_MD_SHA512, SHA512, (uint8_t *)SECRET_KEY_SHA512, SECRET_KEY_SHA512_SZ},
    {0}
};

int main(int argc, char **argv) {
    int
        err,
        table_index=0;
    uint32_t result;
    struct test_table_t *test_table=TEST_TABLE;

    TITLE_MSG("Begin test for CAuth2. Based on https://datatracker.ietf.org/doc/html/rfc6238")
    do {
        err=cauth_2fa_auth_code(
            &result, test_table->type, (uint8_t *)test_table->key, test_table->key_size,
            FALSE, T0, X, &test_table->T, test_table->digit_size
        );

        C_ASSERT_EQUAL_INT(
            ERROR_SUCCESS, err
        )

        C_ASSERT_EQUAL_U32(
            test_table->expected_totp, result,
            CTEST_SETTER(
                CTEST_INFO("Test table index = %d ALG NAME = \"%s\"", ++table_index, test_table->alg_name),
                CTEST_ON_SUCCESS("Expected %u -> OK", test_table->expected_totp),
                CTEST_ON_ERROR("Was expected %u but found %u", test_table->expected_totp, result)
            )
        )
    } while ((++test_table)->alg_name);

    end_tests();
    return 0;
}