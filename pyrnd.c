#include <pthread.h>
#include <python/pyrnd.h>
#include <python/pyrnd.h>
#include <cauth2.h>
// TODO Add thread in Python and callable object

#define rand_entropy_init \
    (RAND_ENTROPY *)malloc(sizeof(RAND_ENTROPY));

#define rand_entropy_finish \
    free(memset((void *)rand_entropy, 0, sizeof(RAND_ENTROPY)));

#define clear_entropy \
    memset((void *)rand_entropy->__entropy_val, 0, sizeof(rand_entropy->__entropy_val));

int verify_system_entropy(
    uint32_t type,
    uint8_t *rand,
    size_t rand_size,
    int *fd
)
{
    int err;
    size_t i;
    uint64_t final;
    RAND_ENTROPY *rand_entropy;

    if (!(rand_entropy=rand_entropy_init))
        return 50;

    err=0;

verify_system_entropy_RET:

    if (cauth_random(rand_entropy->__rand_data, sizeof(rand_entropy->__rand_data), fd, NULL)==FALSE) {
        err=51;
        goto verify_system_entropy_EXIT;
    }

    final=0;

    clear_entropy

    for (i=0;i<DISCRETE_LOG_MAX;i++)
        rand_entropy->__entropy_val[rand_entropy->__rand_data[i]]+=1;

    for (i=0;i<_ENTROPY_NUMBER_OF_ELEMENTS;i++)
        final+=rand_entropy->__entropy_val[i]*_log_discrete_array[rand_entropy->__entropy_val[i]];

    if ((uint64_t)type>final)
        goto verify_system_entropy_RET;

    memcpy((void *)rand, (const void *)rand_entropy->__rand_data, rand_size);

verify_system_entropy_EXIT:
    rand_entropy_finish

    return err;
}
