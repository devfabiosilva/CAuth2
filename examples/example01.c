#include <cauth2.h>
#include <stdio.h>

int main(int argc, char **argv) {

#define SHA1_SECRET "01234567891234567890"
#define SZ(s) sizeof(s)-1
    uint32_t output;
    int err=cauth_2fa_auth_code(
        &output, ALG_SHA1_DEFAULT,
        (uint8_t *)SHA1_SECRET, SZ(SHA1_SECRET),
        FALSE, 0, 30, NULL, 6
    );

    if (err==ERROR_SUCCESS) {
        printf("\nAuthenticator: %u\n", output);
        return 0;
    }

    printf("\nError %d\n", err);
    return 1;
}
