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
