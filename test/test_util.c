#include <stdio.h>
#include <stdint.h>

int gen_rand_no_entropy_util(uint8_t *output, size_t output_len)
{
   #define FILE_NAME "/dev/urandom"
   FILE *f;
   size_t rnd_sz, left;

    if (!output)
        return -3;

    if (!output_len)
        return -2;

    if (!(f=fopen(FILE_NAME, "r")))
        return -1;

    rnd_sz=0;
    left=output_len;

    while ((rnd_sz+=fread((void *)output+rnd_sz, 1, left, f))<output_len)
        left-=rnd_sz;

    fclose(f);

    return 0;

   #undef FILE_NAME
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
