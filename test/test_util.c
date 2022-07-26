#include <unistd.h>
#include <stdint.h>

int gen_rand_no_entropy_util(uint8_t *output, size_t output_len, int *fd)
{
    ssize_t bytes_read;

    if (!output)
        return -3;

    if (!output_len)
        return -2;

    if (((size_t)(bytes_read=read(*fd, (void *)output, output_len)))==output_len)
        return 0;

    return -2;
}

//-1 Fail
// 0 Success
int test_vector(uint8_t *v, size_t v_sz, uint8_t c)
{
    if (!v_sz)
        return -1;

    do
        if (*(v++)!=c)
            return -1;
    while (--v_sz);

    return 0;
}
