#include <pthread.h>
#include <python/pyrnd.h>
#include <python/pyrnd.h>
#include <cauth2.h>
#include <time.h>
// TODO Add thread in Python and callable object
//https://stackoverflow.com/questions/10192903/time-in-milliseconds-in-c
//https://www.man7.org/linux/man-pages/man3/clock_gettime.3.html

_Static_assert(sizeof(uint64_t)==sizeof(time_t), "Wrong timestamp adjust");

static
uint64_t *getCurrentNanoSecond(uint64_t *timestamp)
{
    struct timespec now;

    if (!clock_gettime(CLOCK_MONOTONIC_RAW, &now)) {
        *timestamp=(uint64_t)now->tv_nsec;
        return timestamp;
    }

    return NULL;
}

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
    int *fd,
    uint64_t timeoutInMS
)
{
    int err;
    size_t i;
    uint64_t final, timestamp;
    RAND_ENTROPY *rand_entropy;

    if (!(rand_entropy=rand_entropy_init))
        return 50;

    if (!getCurrentNanoSecond(&timestamp))
        return 51;

    timeoutInMS=(timeoutInMS*1000000)+timestamp;

    err=0;

verify_system_entropy_RET:

    if (cauth_random(rand_entropy->__rand_data, sizeof(rand_entropy->__rand_data), fd, NULL)==FALSE) {
        err=52;
        goto verify_system_entropy_EXIT;
    }

    final=0;

    clear_entropy

    for (i=0;i<DISCRETE_LOG_MAX;i++)
        rand_entropy->__entropy_val[rand_entropy->__rand_data[i]]+=1;

    for (i=0;i<_ENTROPY_NUMBER_OF_ELEMENTS;i++)
        final+=rand_entropy->__entropy_val[i]*_log_discrete_array[rand_entropy->__entropy_val[i]];

    if (!getCurrentNanoSecond(&timestamp)) {
        err=53;
        goto verify_system_entropy_EXIT;
    }

    if (timestamp>timeoutInMS) {
        err=54;
        goto verify_system_entropy_EXIT;
    }

    if ((uint64_t)type>final)
        goto verify_system_entropy_RET;

    memcpy((void *)rand, (const void *)rand_entropy->__rand_data, rand_size);

verify_system_entropy_EXIT:
    rand_entropy_finish

    return err;
}
