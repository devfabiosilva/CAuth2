//Qua 18 Set 2019 00:41:26 -03

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#define LOG_DISCRETE_MAX 8*256

#define LOG_DISCRETE_INF (int) 0x7FFFFFFF

static int F_LOG_ARRAY[LOG_DISCRETE_MAX+1];

#define F_LOG_ARRAY_SZ (size_t)sizeof(F_LOG_ARRAY)/sizeof(uint32_t)

_Static_assert(sizeof(uint32_t)==sizeof(unsigned int), "Adjust integer size");

int main(int argc, char **argv)
{
   uint32_t i, j, k;

   F_LOG_ARRAY[0]=LOG_DISCRETE_INF;

   for (i=1;i<F_LOG_ARRAY_SZ;i++)
      F_LOG_ARRAY[i]=(uint32_t)(-131072*log(((double)i)/((double)LOG_DISCRETE_MAX))); //131072=2^17

   printf("\nconst uint32_t _log_discrete_array[]={");

   for (i=0;i<F_LOG_ARRAY_SZ;) {

      k=i+32;

      if (k>F_LOG_ARRAY_SZ)
         k=F_LOG_ARRAY_SZ;

      for (j=i;j<k;j++)
         printf("\t%u,", (unsigned int)F_LOG_ARRAY[j]);

      printf("\n");

      i=k;
   }

   printf("\n};");

   return 0;
}
