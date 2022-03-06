#include <cauth2.h>
#include <stdio.h>
#include <strings.h>
//https://datatracker.ietf.org/doc/html/rfc6238
// gcc -O2 main.c src/cauth2.c src/CyoDecode.c -Iinclude -Llib -lnanocrypto1 -o test -fsanitize=leak,address
int main(int argc, char **argv)
{
    int err;
    uint32_t result;
#define KEY "MRSTAYZYGQZDCNLBGZRDONBSHFSDGZBSHAZTMZRVGRRDMYRZGE3WGOJTGAYTCMBTGEZTIOJQGQ2DKN3BHEZDQYZVGY2TQMDDMY2WCNA="
//"MRSTAYZYGQZDCNLBGZRDONBSHFSDGZBSHAZTMZRVGRRDMYRZGE3WGOJTGAYTCMBTGEZTIOJQGQ2DKN3BHEZDQYZVGY2TQMDDMY2WCNA="
//"de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4"
//"cd962dd796e56926fd3a"
//"MNSDSNRSMRSDOOJWMU2TMOJSGZTGIM3B"
#define KEYSZ sizeof(KEY)-1

    err=cauth_2fa_auth_code(
        &result, MBEDTLS_MD_SHA1, (uint8_t *)KEY, KEYSZ, 1, 0, 30, NULL, 6
    );

    if (err) {
        printf("Error %d", err);
        return err;
    }

    printf("\nResult %u", result);

    #define MSG "Mensagem aqui"
    #define KEY_2 "Chave mestre@1234"
    #define MSG_SZ sizeof(MSG)-1
    #define KEY_2_SZ sizeof(KEY_2)-1
    uint8_t *signature;
    size_t signature_size;
    char *p;

    if (!(err=sign_message_dynamic(
        &signature, &signature_size,
        MBEDTLS_MD_SHA1,
        KEY_2, KEY_2_SZ,
        MSG, MSG_SZ
    ))) {
        p=cauth_hex2str_dynamic((const uint8_t *)signature, signature_size, IS_LOWER_CASE);
        printf("\nSignature %s @ %p with size %lu\n", p, signature, signature_size);
    } else {
        printf("\nError sign_message_dynamic %d\n", err);
        return err;
    }

    if (cauth_verify_message(
        signature, signature_size,
        MBEDTLS_MD_SHA1,
        KEY_2, KEY_2_SZ,
        MSG, MSG_SZ
    )) printf("Signature is VALID\n");
    else printf("SINGNATURE INVALID");

    free(p);
    free(signature);

    return err;

#undef KEYSZ
#undef KEY
 }
